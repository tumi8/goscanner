package results

import (
	"encoding/csv"
	"encoding/hex"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/ssh"
	"time"
)

type SSHResult struct {
	HostKey                  ssh.PublicKey
	Fingerprint              string
	KexAlgos                 []string
	ServerHostKeyAlgos       []string
	CiphersServerClient      []string
	CiphersClientServer      []string
	MacsServerClient         []string
	MacsClientServer         []string
	CompressionsClientServer []string
	CompressionsServerClient []string
	LanguagesClientServer    []string
	LanguagesServerClient    []string
	SshVersion               string
	ServerVersion            string
	Err                      error
}

func (t SSHResult) GetCsvFileName() string {
	return FileHostKeys
}

func (t SSHResult) GetCsvHeader() []string {
	return []string{
		"key",
		"fingerprint",
		"kex",
		"ServerHostKeyAlgos",
		"CiphersServerClient",
		"CiphersClientServer",
		"MacsServerClient",
		"MacsClientServer",
		"CompressionsClientServer",
		"CompressionsServerClient",
		"LanguagesClientServer",
		"LanguagesServerClient",
		"SshVersion",
		"ServerVersion",
		"Err",
	}
}

func (t SSHResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	hostKey := ""
	if t.HostKey != nil {
		hex.EncodeToString(t.HostKey.Marshal())
	}
	errStr := ""
	if t.Err != nil {
		errStr = t.Err.Error()
	}

	return writer.Write([]string{
		hostKey,
		t.Fingerprint,
		misc.ToJSONArray(t.KexAlgos),
		misc.ToJSONArray(t.ServerHostKeyAlgos),
		misc.ToJSONArray(t.CiphersServerClient),
		misc.ToJSONArray(t.CiphersClientServer),
		misc.ToJSONArray(t.MacsServerClient),
		misc.ToJSONArray(t.MacsClientServer),
		misc.ToJSONArray(t.CompressionsClientServer),
		misc.ToJSONArray(t.CompressionsServerClient),
		misc.ToJSONArray(t.LanguagesClientServer),
		misc.ToJSONArray(t.LanguagesServerClient),
		t.SshVersion,
		t.ServerVersion,
		errStr,
	})
}
