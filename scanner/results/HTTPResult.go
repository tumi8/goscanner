package results

import (
	"encoding/csv"
	log "github.com/sirupsen/logrus"
	"net"
	"strconv"
	"time"
)

var httpCsvHeader = []string{"host", "port", "server_name", "http_method", "http_path", "http_code", "http_headers", "error_data"}

type HTTPResult struct {
	HttpMethod  string
	HttpPath    string
	HttpCode    int
	HttpHeaders string
	HttpError   error
}

func (t *HTTPResult) GetCsvFileName() string {
	return FileHttp
}

func (t *HTTPResult) GetCsvHeader() []string {
	return httpCsvHeader
}

func (t *HTTPResult)  WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool,  cacheFunc func([]byte) []byte, cache map[string]map[string]struct{}) {
	ip, port, err := net.SplitHostPort(parentResult.Address)
	if err != nil {
		log.WithFields(log.Fields{
			"address": parentResult.Address,
		}).Error("Could not split address into host and port parts.")
	}

	errorStr := ""
	if t.HttpError != nil {
		errorStr = t.HttpError.Error()
	}
	if ok := writer.Write([]string{ip, port, parentResult.Domain, t.HttpMethod, t.HttpPath, strconv.Itoa(t.HttpCode), t.HttpHeaders, errorStr}); ok != nil {
		log.WithFields(log.Fields{
			"file": t.GetCsvFileName(),
		}).Error("Error writing to HTTP file")
	}

}
