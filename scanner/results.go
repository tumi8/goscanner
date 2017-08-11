package scanner

import (
	"time"
)

// ScanResult contains the time when the measurement occurred and the result
type ScanResult struct {
	synStart time.Time
	synEnd   time.Time
	scanEnd  time.Time
	result   interface{}
}

// ResultProcessor has one function for processing results, additionally Prepare and Finish functions
type ResultProcessor interface {
	Prepare()
	ProcessResult(*Target)
	Finish()
}

// Processor is the base result processing struct, embedding a ResultProcessor
type Processor struct {
	ResultProcessor
	OutputChan <-chan *Target
}

// Process is the result processing loop which calls the functions of the embedded ResultProcessor
func (p Processor) Process() {
	p.Prepare()
	for res := range p.OutputChan {
		p.ProcessResult(res)
	}
	p.Finish()
}
