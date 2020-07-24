package scanner

import (
	"encoding/csv"
	"encoding/hex"
	"errors"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"
)

type ResultProcessor interface {
	Prepare()
	ProcessResult(*results.BatchScanResult)
	Finish()
}

// Processor is the base result processing struct, embedding a ResultProcessor
type Processor struct {
	ResultProcessor
	OutputChan <-chan *results.BatchScanResult
}

// Process is the result processing loop which calls the functions of the embedded ResultProcessor
func (p Processor) Process() {
	p.Prepare()
	for res := range p.OutputChan {
		p.ProcessResult(res)
	}
	p.Finish()
}

type CsvProcessor struct {
	outputDir	string
	csvWriter	map[string]*csv.Writer
	files 		[]*os.File
	fileLocks	sync.Map
	skipErrors	bool
	cacheFunc	func([]byte) []byte
	cache 		map[string]map[string]struct{}
}

func NewCsvProcessor(outputDir string, skipErrors bool, cacheFunc func([]byte) []byte) CsvProcessor {
	return CsvProcessor{
		outputDir:  outputDir,
		csvWriter:  make(map[string]*csv.Writer),
		files:      make([]*os.File, 0),
		fileLocks:  sync.Map{},
		skipErrors: skipErrors,
		cacheFunc:  cacheFunc,
		cache:      make(map[string]map[string]struct{}),
	}
}

func (p CsvProcessor) Prepare() {}
func (p CsvProcessor) Finish() {
	for _, writer := range p.csvWriter {
		writer.Flush()
	}
	for _, file := range p.files {
		file.Close()
	}
}
func (p CsvProcessor) ProcessResult(batch *results.BatchScanResult) {
	for _, result := range batch.Results {
		for _, subResult := range result.SubResults {
			fileName := filepath.Join(p.outputDir, subResult.Result.GetCsvFileName())
			var lock sync.Mutex
			lock2, _ := p.fileLocks.LoadOrStore(fileName, sync.Mutex{})
			lock = lock2.(sync.Mutex)
			lock.Lock()
			if p.csvWriter[fileName] == nil {
				file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
				p.files = append(p.files, file)
				if err != nil {
					log.Println("Error while opening file " + fileName, err)
				}
				p.csvWriter[fileName] = csv.NewWriter(file)
				p.csvWriter[fileName].Write(subResult.Result.GetCsvHeader())
			}
			subResult.Result.WriteCsv(p.csvWriter[fileName], result, subResult.SynStart, subResult.SynEnd, subResult.ScanEnd, p.skipErrors, p.cacheFunc, p.cache)
			lock.Unlock()
		}
	}
}


// TLSLiveProcessor implements the processing of TLS scanning results
type TLSLiveProcessor struct {
	jsonFile  *os.File
	certDir   string
	tableName string
}
// NewTLSLiveProcessor returns a new processor for results of live scanned TLS hosts
func NewTLSLiveProcessor(jsonFilename, certDir, tableName string) (*ResultProcessor, error) {
	t := TLSLiveProcessor{}

	// Create a new file for JSON output, returns an error if it already exists
	fh, err := os.OpenFile(jsonFilename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return nil, err
	}
	t.jsonFile = fh

	t.certDir = certDir
	t.tableName = tableName

	var r ResultProcessor
	r = t

	return &r, nil
}

// Prepare is called before the results are being processed
func (t TLSLiveProcessor) Prepare() {
	t.jsonFile.Write([]byte{'['})
}
// Finish is called after the results have been processed
func (t TLSLiveProcessor) Finish() {
	info, err := t.jsonFile.Stat()
	if err != nil {
		log.WithFields(log.Fields{
			"file": t.jsonFile.Name(),
		}).Fatal(err)
	}

	// Do not seek back if the input was an empty JSON list []
	if info.Size() > 1 {
		t.jsonFile.Seek(-1, 1)
	}

	// Write closing bracket and close file
	t.jsonFile.Write([]byte{']'})
	t.jsonFile.Close()
}
// ProcessResult checks the database, writes the JSON output and dumps the certificate chain
func (t TLSLiveProcessor) ProcessResult(in *results.BatchScanResult) {

	for _, result := range in.Results {
		for _, subResult := range result.SubResults {
			cert, ok := subResult.Result.(*results.CertResult)
			if ok {
				// The resulting filename is the base directory concatenated with the IP address, the Unix timestamp and the number of certificate in the chain
				filename := filepath.Join(t.certDir, result.Address+"-"+strconv.FormatInt(subResult.ScanEnd.Unix(), 10)+"-"+strconv.Itoa(cert.Depth)+".der")

				// Create a new file for the cert dump, returns an error if it already exists
				fh, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
				if err != nil {
					log.Errorln("Could not open file " + filename, err)
					continue
				}
				defer fh.Close()

				// Dump raw DER-encoded certificate
				fh.Write(cert.Cert.Raw)
			}
		}
	}

	// Get database handle
	db, err := PostgresDb("host=/var/run/postgresql sslmode=disable user=heap dbname=tlshashes", t.tableName)
	if err != nil {
		log.Fatal("Could not get database handle: ", err)
	}
	defer db.Close()

	// Check the database for all results
	for _, result := range in.Results {
		for _, subResult := range result.SubResults {

			// Try to convert the result in a TLSResult
			tlsRes, ok := subResult.Result.(*results.TLSResult)
			if !ok || tlsRes.Err != nil {
				// Most probably the result is an error
				continue
			}

			// Extract public key from leaf certificate
			cert := tlsRes.Certificates[len(tlsRes.Certificates)-1]
			if err != nil {
				// Only RSA and ECDSA public keys are supported
				result.AddResult(results.ScanSubResult{subResult.SynStart, subResult.SynEnd, subResult.ScanEnd, &results.TLSResult{nil, tlsRes.Version, tlsRes.Cipher, err}})
				continue
			}
			hash := misc.GetSHA256(cert.Raw)

			// Certificate is not in database
			if !db.QueryChecksum(result.Address, hex.EncodeToString(hash)) {
				result.AddResult(results.ScanSubResult{subResult.SynStart, subResult.SynEnd, subResult.ScanEnd, &results.TLSResult{nil, tlsRes.Version, tlsRes.Cipher, errors.New("certificate not in database")}})
			}
		}
	}

	// Write results to JSON file
	output, err := CreateSubmoasOutput(in.Input, &in.Results)
	if err != nil {
		log.Fatal("Error creating JSON output", err)
	}

	// Don't write enclosing '[' and ']'
	t.jsonFile.Write(output[1 : len(output)-1])

	// Append ','
	t.jsonFile.Write([]byte{','})
}