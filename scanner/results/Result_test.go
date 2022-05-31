package results

import (
	"bytes"
	"crypto/x509"
	"encoding/csv"
	"errors"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/tls"
	"reflect"
	"testing"
	"time"
)

var allResults = []Result{
	&CertResult{
		Cert: &x509.Certificate{},
	},
	&HTTPResult{},
	&SCSVResult{
		Err: errors.New("test"),
	},
	&SSHResult{},
	&TLSFingerprintResult{
		TLSState: tls.ConnectionState{
			ServerHello: &tls.ServerHelloMsg{},
		},
	},
	&TLSResult{},
	&TCPResult{},
	&StapledOCSPResult{},
}

func init() {
	allResults = append(allResults, &CertRelationResult{
		Chain: []x509.Certificate{{}},
	})
}

func Test_headerLength(t *testing.T) {

	scanResult := ScanResult{
		Ip:      "192.168.1.1",
		Domain:  "example.com",
		Address: "192.168.1.1:80",
	}

	cache := misc.NewCertCache(misc.GetSHA256)

	for _, result := range allResults {

		header := result.GetCsvHeader()
		name := reflect.TypeOf(result).Elem().Name()

		t.Run("Testing "+name, func(t *testing.T) {
			buffer := new(bytes.Buffer)
			writer := csv.NewWriter(buffer)

			err := result.WriteCsv(writer, &scanResult, time.Now(), time.Now(), time.Now(), false, cache)

			if err != nil {
				t.Errorf("Resutl returned an error %v", err.Error())
			}
			writer.Flush()
			records, err := csv.NewReader(buffer).ReadAll()
			if len(records) != 1 {
				t.Errorf("Result return multiple results %v", len(records))
			}

			for _, record := range records {
				if len(record) != len(header) {
					t.Errorf("The Result returned %v entries, that does not match the header length %v. Maybe you forgot to update the header?", len(record), len(header))
				}
			}
		})
	}
}
