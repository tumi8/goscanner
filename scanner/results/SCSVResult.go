package results

import (
	"encoding/csv"
	"github.com/tumi8/goscanner/scanner/misc"
	"strconv"
	"time"
)

var scsvCsvHeader = []string{"id", "time", "time_end", "scan_end", "protocol", "cipher", "error_data"}

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

func (t *SCSVResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	// Check protocol and cipher
	protocol := strconv.Itoa(int(t.Version))
	cipher := strconv.FormatUint(uint64(t.Cipher), 16)

	return writer.Write([]string{parentResult.Id.ToString(), strconv.FormatInt(synStart.Add(timeDiff).Unix(), 10), strconv.FormatInt(synEnd.Add(timeDiff).Unix(), 10), strconv.FormatInt(scanEnd.Add(timeDiff).Unix(), 10), protocol, cipher, t.Err.Error()})
}
