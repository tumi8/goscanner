package results

import (
	"encoding/base64"
	"encoding/csv"
	"github.com/tumi8/goscanner/scanner/misc"
	"time"
)

var stapledOCSPHeader = []string{"host_id", "stapled_ocsp_response"}

type StapledOCSPResult struct {
	OCSPResponseBytes []byte
}

func (t StapledOCSPResult) GetCsvFileName() string {
	return FileStapledOCSP
}

func (t StapledOCSPResult) GetCsvHeader() []string {
	return stapledOCSPHeader
}

func (t StapledOCSPResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	return writer.Write([]string{
		parentResult.Id.ToString(),
		base64.StdEncoding.EncodeToString(t.OCSPResponseBytes),
	})
}
