package results

import (
	"encoding/csv"
	log "github.com/sirupsen/logrus"
	"net"
	"strconv"
	"time"
)

var scsvCsvHeader = []string{"host", "port", "server_name", "time", "protocol", "cipher", "error_data"}

type SCSVResult struct {
	Version uint16
	Cipher  uint16
	Err     error
}


func (t *SCSVResult) GetCsvFileName() string {
	return FileScsv
}

func (t *SCSVResult) GetCsvHeader() []string {
	return scsvCsvHeader
}

func (t *SCSVResult)  WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool,  cacheFunc func([]byte) []byte, cache map[string]map[string]struct{}) {
	ip, port, err := net.SplitHostPort(parentResult.Address)
	if err != nil {
		log.WithFields(log.Fields{
			"address": parentResult.Address,
		}).Error("Could not split address into host and port parts.")
	}

	// Check protocol and cipher
	var protocol, cipher string
	var ok bool
	if protocol, ok = cipherSuites[t.Version]; !ok {
		protocol = "not set"
	}
	if cipher, ok = cipherSuites[t.Cipher]; !ok {
		cipher = "not set"
	}

	if ok := writer.Write([]string{ip, port, parentResult.Domain, strconv.FormatInt(synStart.Add(timeDiff).Unix(), 10), strconv.FormatInt(synEnd.Add(timeDiff).Unix(), 10), strconv.FormatInt(scanEnd.Add(timeDiff).Unix(), 10), protocol, cipher, t.Err.Error()}); ok != nil {
		log.WithFields(log.Fields{
			"file": t.GetCsvFileName(),
		}).Error("Error writing to SCSV file")
	}
}
