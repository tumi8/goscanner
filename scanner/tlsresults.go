package scanner

import (
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// Hash cache enum
	HashCacheSHA256 = 1
	HashCacheSHA1   = 2
	HashCacheNone   = 3
)

// beginPublicKey and endPublicKey signal start and beginning of PEM-encoded TLS public keys
const beginPublicKey = "-----BEGIN PUBLIC KEY-----"
const endPublicKey = "-----END PUBLIC KEY-----"

// hostCsvHeader represents the header line of the hosts.csv file
var hostCsvHeader = []string{"host", "rtt", "port", "server_name", "synStart", "synEnd", "scanEnd", "protocol", "cipher", "resultString", "verify_err_no", "verify_code", "server_version", "depth", "depth_verbose", "error_data", "cert_hash", "pub_key_hash"}

// chrCsvHeader represents the header line of the cert_host_rel.csv file
var chrCsvHeader = []string{"cert_hash", "parent_cert_hash"}

// certCsvHeader represents the header line of the certs.csv file
var certCsvHeader = []string{"cert", "cert_hash"}

// scsvCsvHeader represents the header line of the scsv.csv file
var scsvCsvHeader = []string{"host", "port", "server_name", "time", "protocol", "cipher", "error_data"}

// httpCsvHeader represents the header line of the http.csv file
var httpCsvHeader = []string{"host", "port", "server_name", "http_method", "http_path", "http_code", "http_headers", "error_data"}

// TLSLiveProcessor implements the processing of TLS scanning results
type TLSLiveProcessor struct {
	jsonFile  *os.File
	certDir   string
	tableName string
}

// TLSResult is an instance of result from ScanResult with TLS certificates, version and cipher
type TLSResult struct {
	certificates []*x509.Certificate
	version      uint16
	cipher       uint16
	err          error
}

// HTTPResult is the result of a HTTPS connection with a specific HTTP request
type HTTPResult struct {
	httpMethod  string
	httpPath    string
	httpCode    int
	httpHeaders string
	httpError   error
}

// SCSVResult is the result of a TLS handshake with the SCSV downgrade protection pseudo cipher
type SCSVResult struct {
	version uint16
	cipher  uint16
	err     error
}

// NewTLSLiveProcessor returns a new processor for results of live scanned TLS hosts
func NewTLSLiveProcessor(jsonFilename, certDir, tableName string) (ResultProcessor, error) {
	t := TLSLiveProcessor{}

	// Create a new file for JSON output, returns an error if it already exists
	fh, err := os.OpenFile(jsonFilename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return nil, err
	}
	t.jsonFile = fh

	t.certDir = certDir
	t.tableName = tableName

	return t, nil
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
func (t TLSLiveProcessor) ProcessResult(hIn *Target) {

	// Cast to correct target type
	h, ok := (*hIn).(*MultiTLSTarget)
	if !ok {
		log.Fatal("Did not pass MultiTLSTarget to ProcessResult()")
	}

	// Dump certificates
	err := h.Dump(t.certDir)
	if err != nil {
		log.WithFields(log.Fields{
			"directory": t.certDir,
		}).Fatal("Error dumping certificates", err)
	}

	// Get database handle
	db, err := PostgresDb("host=/var/run/postgresql sslmode=disable user=heap dbname=tlshashes", t.tableName)
	if err != nil {
		log.Fatal("Could not get database handle: ", err)
	}
	defer db.Close()

	// Check the database for all results
	for address, res := range (*h).Results() {

		// Try to convert the result in a TLSResult
		tlsRes, ok := res.result.(TLSResult)
		if !ok || tlsRes.err != nil {
			// Most probably the result is an error
			continue
		}

		// Extract public key from leaf certificate
		cert := tlsRes.certificates[len(tlsRes.certificates)-1]
		if err != nil {
			// Only RSA and ECDSA public keys are supported
			h.AddResult(address, &ScanResult{res.synStart, res.synEnd, res.scanEnd, TLSResult{nil, tlsRes.version, tlsRes.cipher, err}})
			continue
		}
		hash := getSHA256(cert.Raw)

		// Certificate is not in database
		if !db.QueryChecksum(address, hex.EncodeToString(hash)) {
			h.AddResult(address, &ScanResult{res.synStart, res.synEnd, res.scanEnd, TLSResult{nil, tlsRes.version, tlsRes.cipher, errors.New("certificate not in database")}})
		}
	}

	// Write results to JSON file
	output, err := h.JSON()
	if err != nil {
		log.Fatal("Error creating JSON output", err)
	}

	// Don't write enclosing '[' and ']'
	t.jsonFile.Write(output[1 : len(output)-1])

	// Append ','
	t.jsonFile.Write([]byte{','})
}

// TLSDumpProcessor implements the processing of TLS scanning results
type TLSDumpProcessor struct {
	certDir string
}

// NewTLSDumpProcessor returns a new processor for results of live scanned TLS hosts
func NewTLSDumpProcessor(certDir string) (ResultProcessor, error) {
	t := TLSDumpProcessor{}
	t.certDir = certDir

	return t, nil
}

// Prepare is called before the results are being processed
func (t TLSDumpProcessor) Prepare() {

}

// Finish is called after the results have been processed
func (t TLSDumpProcessor) Finish() {

}

// ProcessResult dumps the certificate chain
func (t TLSDumpProcessor) ProcessResult(hIn *Target) {
	// Cast to correct target type
	h, ok := (*hIn).(*DumpTLSTarget)
	if !ok {
		log.Fatal("Did not pass DumpTLSTarget to ProcessResult()")
	}

	// Dump certificates
	err := h.Dump(t.certDir)
	if err != nil {
		log.WithFields(log.Fields{
			"directory": t.certDir,
		}).Error("Error dumping certificates", err)
	}
}

// TLSCertHostProcessor implements the processing of TLS scanning results
type TLSCertHostProcessor struct {
	hostFh       *os.File
	certFh       *os.File
	chrFh        *os.File
	scsvFh       *os.File
	httpFh       *os.File
	timeDiff     time.Duration
	certCache    map[string]map[string]struct{}
	cipherSuites map[uint16]string
	skipErrors   bool
	cacheFunc    func([]byte) []byte
}

// NewTLSCertHostProcessor returns a new processor for results of scanned TLS hosts
func NewTLSCertHostProcessor(certfile, hostfile, chrfile, scsvfile, httpfile string, skipErrors bool, hashCache int) ResultProcessor {
	t := TLSCertHostProcessor{}

	// Host file
	hostFh, err := os.OpenFile(hostfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.WithFields(log.Fields{
			"file": hostfile,
		}).Fatal("Can not open host file")
	}
	t.hostFh = hostFh

	// Certificate file
	certFh, err := os.OpenFile(certfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.WithFields(log.Fields{
			"file": certfile,
		}).Fatal("Can not open certificate file")
	}
	t.certFh = certFh

	// Certificate Host Relations file
	chrFh, err := os.OpenFile(chrfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.WithFields(log.Fields{
			"file": chrfile,
		}).Fatal("Can not open host-certificate-relationship file")
	}
	t.chrFh = chrFh

	// Write CSV headers
	writeHeader := csv.NewWriter(t.hostFh)
	writeHeader.Write(hostCsvHeader)
	writeHeader.Flush()

	writeHeader = csv.NewWriter(t.certFh)
	writeHeader.Write(certCsvHeader)
	writeHeader.Flush()

	writeHeader = csv.NewWriter(t.chrFh)
	writeHeader.Write(chrCsvHeader)
	writeHeader.Flush()

	// SCSV file
	if scsvfile != "" {
		scsvFh, err := os.OpenFile(scsvfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.WithFields(log.Fields{
				"file": scsvfile,
			}).Fatal("Can not open SCSV file")
		}
		t.scsvFh = scsvFh

		writeHeader = csv.NewWriter(t.scsvFh)
		writeHeader.Write(scsvCsvHeader)
		writeHeader.Flush()
	}

	// HTTP file
	if httpfile != "" {
		httpFh, err := os.OpenFile(httpfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.WithFields(log.Fields{
				"file": httpfile,
			}).Fatal("Can not open HTTP file")
		}
		t.httpFh = httpFh

		writeHeader = csv.NewWriter(t.httpFh)
		writeHeader.Write(httpCsvHeader)
		writeHeader.Flush()
	}

	// Cache for already exported certificates
	t.certCache = make(map[string]map[string]struct{}, 256)

	t.timeDiff = getNtpLocalTimeDiff()

	// Read TLS cipher suites
	t.cipherSuites = ReadCiphersFromAsset()

	t.skipErrors = skipErrors

	if hashCache == HashCacheSHA1 {
		t.cacheFunc = getSHA1
	} else if hashCache == HashCacheSHA256 {
		t.cacheFunc = getSHA256
	} else if hashCache == HashCacheNone {
		t.cacheFunc = nil
	}

	return t
}

// Prepare is called before the results are being processed
func (t TLSCertHostProcessor) Prepare() {

}

// Finish is called after the results have been processed
func (t TLSCertHostProcessor) Finish() {
	if ok := t.hostFh.Close(); ok != nil {
		log.WithFields(log.Fields{
			"file": t.hostFh.Name(),
		}).Error("Error closing host file")
	}
	if ok := t.certFh.Close(); ok != nil {
		log.WithFields(log.Fields{
			"file": t.certFh.Name(),
		}).Error("Error closing certificate file")
	}
	if ok := t.chrFh.Close(); ok != nil {
		log.WithFields(log.Fields{
			"file": t.chrFh.Name(),
		}).Error("Error closing host-certificate-relationship file")
	}
	if t.scsvFh != nil {
		if ok := t.scsvFh.Close(); ok != nil {
			log.WithFields(log.Fields{
				"file": t.scsvFh.Name(),
			}).Error("Error closing SCSV file")
		}
	}
	if t.httpFh != nil {
		if ok := t.httpFh.Close(); ok != nil {
			log.WithFields(log.Fields{
				"file": t.httpFh.Name(),
			}).Error("Error closing HTTP file")
		}
	}
}

// ProcessResult dumps the certificate chain
func (t TLSCertHostProcessor) ProcessResult(hIn *Target) {
	// Cast to correct target type
	h, ok := (*hIn).(*CertHostTLSTarget)
	if !ok {
		log.Fatal("Error did not pass CertHostTLSTarget to ProcessResult()")
	}
	// Dump certificates
	err := h.Dump(t.hostFh, t.certFh, t.chrFh, t.scsvFh, t.httpFh, t.timeDiff, t.certCache, t.cipherSuites, t.skipErrors, t.cacheFunc)
	if err != nil {
		log.WithFields(log.Fields{
			"host file":                          t.hostFh.Name(),
			"certificate file":                   t.certFh.Name(),
			"host-certificate-relationship file": t.chrFh.Name(),
		}).Error("Error dumping certificates", err)
	}
}
