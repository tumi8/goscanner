package results

import (
	"encoding/csv"
	"github.com/tumi8/goscanner/scanner/misc"
	"strconv"
	"time"
)

var HttpExtendedCsvHeader = []string{"id", "position", "header", "content"}

type HTTPExtendedResult struct {
	Header   string
	Position int
	Content  string
}

func (t *HTTPExtendedResult) GetCsvFileName() string {
	return FileHttpVerbose
}

func (t *HTTPExtendedResult) GetCsvHeader() []string {
	return HttpExtendedCsvHeader
}

func (t *HTTPExtendedResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	return writer.Write([]string{
		parentResult.Id.ToString(),
		strconv.Itoa(t.Position),
		t.Header,
		t.Content,
	})
}
