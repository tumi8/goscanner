package results

import (
	"encoding/csv"
	"github.com/tumi8/goscanner/scanner/misc"
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
	FileCertHostRel = "cert_chain.csv"
	FileScsv        = "scsv.csv"
	FileHttp        = "http.csv"
	FileHttpVerbose = "http_verbose.csv"
	FileTLSVerbose  = "tls_verbose.csv"
	FileDissecTLS   = "dissectls.csv"
	FileStapledOCSP = "stapled_ocsp_responses.csv"
	FileJarm        = "jarm.csv"
	FileKeyLog      = "tls-keylog"

	// FileLdap file to save LDAP results
	FileLdap = "ldap.csv"
)

type ScanResult struct {
	SubResults []ScanSubResult
	Id         misc.SessionUID
	Ip         string
	Domain     string
	Address    string
	CHName     string
}

// ScanSubResult contains the time when the measurement occurred and the result
type ScanSubResult struct {
	SynStart time.Time
	SynEnd   time.Time
	ScanEnd  time.Time
	Result   Result
}

type Result interface {
	GetCsvFileName() string
	GetCsvHeader() []string
	WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error
}

func (s *ScanResult) AddResult(r ScanSubResult) {
	s.SubResults = append(s.SubResults, r)
}
