package results

import (
	"encoding/csv"
	"github.com/tumi8/goscanner/scanner/misc"
	"time"
)

var JarmCsvHeader = []string{"id", "fingerprint", "fingerprint_raw", "error_data"}

type JARMResult struct {
	Fingerprint string
	Raw         string
	Error       error
}

func (t *JARMResult) GetCsvFileName() string {
	return FileJarm
}

func (t *JARMResult) GetCsvHeader() []string {
	return JarmCsvHeader
}

func (t *JARMResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	errorStr := ""
	if t.Error != nil {
		errorStr = t.Error.Error()
	}

	return writer.Write([]string{
		parentResult.Id.ToString(),
		t.Fingerprint,
		t.Raw,
		errorStr,
	})
}
