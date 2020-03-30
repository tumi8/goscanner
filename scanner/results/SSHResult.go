package results

import (
	"encoding/csv"
	"github.com/tumi8/ssh"
	"log"
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
	log.Fatal("Not implemented")
	return ""
}

func (t SSHResult) GetCsvHeader() []string {
	log.Fatal("Not implemented")
	return nil
}

func (t SSHResult)  WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool,  cacheFunc func([]byte) []byte, cache map[string]map[string]struct{}) {
	log.Fatal("Not implemented")
}
