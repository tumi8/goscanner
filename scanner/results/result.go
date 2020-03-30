package results

import (
	"encoding/csv"
	"sync"
	"time"
)

// Output files
const (
	FileHosts = "hosts.csv"

	// files to save SSH scan results
	FileHostKeys  = "host_keys.csv"
	FileRelations = "relations.csv"

	// files to save TLS scan results
	FileCerts       = "certs.csv"
	FileCertHostRel = "cert_host_rel.csv"
	FileScsv        = "scsv.csv"
	FileHttp        = "http.csv"
)

type ScanResult struct {
	SubResults	[]ScanSubResult
	Ip			string
	Domain 		string
	resultMutex	sync.Mutex
	Address		string
}

// ScanResult contains the time when the measurement occurred and the result
type ScanSubResult struct {
	SynStart time.Time
	SynEnd   time.Time
	ScanEnd  time.Time
	Result   Result
}

type BatchScanResult struct {
	Input  string
	Results []*ScanResult
}

type Result interface {
	GetCsvFileName() string
	GetCsvHeader() []string
	WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool,  cacheFunc func([]byte) []byte, cache map[string]map[string]struct{})
}

func (s *ScanResult) AddResult(r ScanSubResult) {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()
	s.SubResults = append(s.SubResults, r)
}
