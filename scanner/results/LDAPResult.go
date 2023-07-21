package results

import (
	"encoding/csv"
	"github.com/tumi8/goscanner/scanner/misc"
	"strconv"
	"time"
)

type LDAPResult struct {
	HasStartTLS bool
	LdapError   error
}

type StartTLSLDAPResult struct {
	HasStartTLS bool
}

func (t *LDAPResult) GetCsvFileName() string {
	return FileLdap
}

func (t *LDAPResult) GetCsvHeader() []string {
	return []string{
		"id",
		"starttls",
		"error_data",
	}
}

func (t *LDAPResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	errorStr := ""
	if t.LdapError != nil {
		errorStr = t.LdapError.Error()
	}

	return writer.Write([]string{
		parentResult.Id.ToString(),
		strconv.FormatBool(t.HasStartTLS),
		errorStr,
	})

}
