package results

import (
	"encoding/csv"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"net"
	"strconv"
	"time"
)

type TCPResult struct {
	Err error
}

func (t *TCPResult) GetCsvFileName() string {
	return FileHosts
}

func (t *TCPResult) GetCsvHeader() []string {
	return hostCsvHeader
}

func (t *TCPResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	ip, port, err := net.SplitHostPort(parentResult.Address)
	if err != nil {
		log.Err(err).Str("address", parentResult.Address).Msg("Could not split address into host and port parts.")
	}

	resultString := "SUCCESS"
	var handshakeErrors []string
	if t.Err != nil {
		handshakeErrors = append(handshakeErrors, t.Err.Error())
		resultString = HandshakeErrorLookup(t.Err)
		if skipErrors {
			for _, e := range skippedErrors {
				if resultString == e {
					return nil
				}
			}
		}
	}

	return writer.Write([]string{
		parentResult.Id.ToString(),
		ip,
		port,
		parentResult.Domain,
		strconv.FormatInt(synStart.Add(timeDiff).Unix(), 10),
		strconv.FormatInt(synEnd.Add(timeDiff).Unix(), 10),
		"",
		"",
		"",
		resultString,
		misc.ToJSONArray(handshakeErrors),
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		parentResult.CHName,
	})
}
