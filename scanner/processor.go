package scanner

import (
	"encoding/csv"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"os"
	"path/filepath"
	"sync"
)

type ResultProcessor interface {
	Prepare()
	ProcessResult(*results.ScanResult)
	Finish()
}

// Processor is the base result processing struct, embedding a ResultProcessor
type Processor struct {
	ResultProcessor
	OutputChan <-chan *results.ScanResult
}

// Process is the result processing loop which calls the functions of the embedded ResultProcessor
func (p Processor) Process() {
	p.Prepare()
	for res := range p.OutputChan {
		p.ProcessResult(res)
	}
	p.Finish()
}

type outputTuple struct {
	parent         *results.ScanResult
	subResultIndex int
}

type CsvProcessor struct {
	outputDir  string
	csvOutputs map[string]chan outputTuple
	skipErrors bool
	certCache  *misc.CertCache
	wg         sync.WaitGroup
}

func NewCsvProcessor(outputDir string, skipErrors bool, cacheFunc func([]byte) []byte) *CsvProcessor {
	return &CsvProcessor{
		outputDir:  outputDir,
		csvOutputs: make(map[string]chan outputTuple),
		skipErrors: skipErrors,
		certCache:  misc.NewCertCache(cacheFunc),
	}
}

func (p *CsvProcessor) Prepare() {}
func (p *CsvProcessor) Finish() {
	for i := range p.csvOutputs {
		close(p.csvOutputs[i])
	}
	p.wg.Wait()
}

func (p *CsvProcessor) ProcessResult(result *results.ScanResult) {
	hasHostsCsv := false
	for i := range result.SubResults {
		if result.SubResults[i].Result.GetCsvFileName() == results.FileHosts {
			hasHostsCsv = true
		}
		p.ProcessSubResult(result, i)
	}
	if !hasHostsCsv {
		// In some cases it might happen that nothing was written into the hosts.csv
		// In these cases we can just write a small entry containing the ID to Host mappings
		sub2 := results.ScanSubResult{}
		if len(result.SubResults) > 0 {
			sub2 = result.SubResults[0]
		}
		sub2.Result = &results.TCPResult{}
		result.AddResult(sub2)
		p.ProcessSubResult(result, len(result.SubResults)-1)
	}
}

func (p *CsvProcessor) ProcessSubResult(parent *results.ScanResult, subResultIndex int) {
	fileName := filepath.Join(p.outputDir, parent.SubResults[subResultIndex].Result.GetCsvFileName())

	if p.csvOutputs[fileName] == nil {
		p.csvOutputs[fileName] = make(chan outputTuple, 10)
		p.wg.Add(1)
		go p.StartOutputWriter(fileName, parent.SubResults[subResultIndex].Result.GetCsvHeader())
	}
	p.csvOutputs[fileName] <- outputTuple{
		parent:         parent,
		subResultIndex: subResultIndex,
	}
}

func (p *CsvProcessor) StartOutputWriter(fileName string, header []string) {
	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Panic().Err(err).Str("file", fileName).Msg("Error Opening file")
	}
	defer file.Close()
	defer p.wg.Done()

	csvWriter := csv.NewWriter(file)
	err = csvWriter.Write(header)
	if err != nil {
		log.Panic().Err(err).Str("file", fileName).Msg("Error writing header")
	}

	for input := range p.csvOutputs[fileName] {
		subResult := input.parent.SubResults[input.subResultIndex]
		err := subResult.Result.WriteCsv(csvWriter, input.parent, subResult.SynStart, subResult.SynEnd, subResult.ScanEnd, p.skipErrors, p.certCache)
		if err != nil {
			log.Err(err).Str("file", fileName).Str("Address", input.parent.Address).Str("Domain", input.parent.Domain).Msg("Error writing CSV output to file")
		}
	}
	csvWriter.Flush()
}
