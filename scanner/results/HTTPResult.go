package results

import (
	"encoding/csv"
	"github.com/tumi8/goscanner/scanner/misc"
	"strconv"
	"strings"
	"time"
)

var HttpCsvHeader = []string{"id", "protocol", "http_method", "http_path", "http_code", "error_data"}

type HTTPResult struct {
	Protocol    string
	HttpMethod  string
	HttpPath    string
	HttpCode    int
	HttpHeaders []string
	HttpError   error
}

func (t *HTTPResult) GetCsvFileName() string {
	return FileHttp
}

func (t *HTTPResult) GetCsvHeader() []string {
	return HttpCsvHeader
}

func (t *HTTPResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	errorStr := ""
	if t.HttpError != nil {
		errorStr = t.HttpError.Error()
	}

	return writer.Write(
		append([]string{
			parentResult.Id.ToString(),
			strings.TrimPrefix(t.Protocol, "HTTP/"),
			t.HttpMethod,
			t.HttpPath,
			strconv.Itoa(t.HttpCode),
			errorStr,
		},
			t.HttpHeaders...))

}
