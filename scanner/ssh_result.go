package scanner

import (
	"encoding/csv"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tumi8/ssh"
)

// sshHostCsvHeader represents the header line of the hosts.csv file
var sshHostCsvHeader = []string{"host", "port", "syn_start", "syn_end", "scan_end", "ssh_version", "server_version", "server_host_key_algos", "ciphers_server_client", "ciphers_client_server", "macs_server_client", "macs_client_server", "kex_algos", "languages_server_client", "languages_client_server", "compressions_server_client", "compressions_client_server", "error_data"}

// sshRelationCsvHeader represents the header line of the relations.csv file
var sshRelationCsvHeader = []string{"fingerprint", "host", "port"}

// sshHostKeyCsvHeader represents the header line of the hostKeys.csv file
var sshHostKeyCsvHeader = []string{"host_key", "fingerprint"}

// SSHResult is an instance of result from ScanResult with SSH host keys, version and cipher
type SSHResult struct {
	hostKey                  ssh.PublicKey
	fingerprint              string
	kexAlgos                 []string
	serverHostKeyAlgos       []string
	ciphersServerClient      []string
	ciphersClientServer      []string
	macsServerClient         []string
	macsClientServer         []string
	compressionsClientServer []string
	compressionsServerClient []string
	languagesClientServer    []string
	languagesServerClient    []string
	sshVersion               string
	serverVersion            string
	err                      error
}

// SSHHostKeyHostProcessor implements the processing of SSH scanning results
type SSHHostKeyHostProcessor struct {
	hostFh       *os.File
	keyFh        *os.File
	relFh        *os.File
	timeDiff     time.Duration
	hostKeyCache map[string]bool
	skipErrors   bool
}

// NewSSHHostKeyHostProcessor returns a new processor for results of scanned SSH hosts
func NewSSHHostKeyHostProcessor(hostkeyfile, hostfile, relfile string, skipErrors bool) ResultProcessor {
	t := SSHHostKeyHostProcessor{}

	// Host file
	hostFh, err := os.OpenFile(hostfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.WithFields(log.Fields{
			"file": hostfile,
		}).Fatal("Can not open host file")
	}
	t.hostFh = hostFh

	// host key file
	keyFh, err := os.OpenFile(hostkeyfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.WithFields(log.Fields{
			"file": hostkeyfile,
		}).Fatal("Can not open host key file")
	}
	t.keyFh = keyFh

	// hostKey-host Relations file
	relFh, err := os.OpenFile(relfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.WithFields(log.Fields{
			"file": relfile,
		}).Fatal("Can not open hostKey-host relationship file")
	}
	t.relFh = relFh

	// Write CSV headers
	writeHeader := csv.NewWriter(t.hostFh)
	writeHeader.Write(sshHostCsvHeader)
	writeHeader.Flush()

	writeHeader = csv.NewWriter(t.keyFh)
	writeHeader.Write(sshHostKeyCsvHeader)
	writeHeader.Flush()

	writeHeader = csv.NewWriter(t.relFh)
	writeHeader.Write(sshRelationCsvHeader)
	writeHeader.Flush()

	// Cache for already exported certificates
	t.hostKeyCache = make(map[string]bool)

	t.timeDiff = getNtpLocalTimeDiff()

	t.skipErrors = skipErrors

	return t
}

// Prepare is called before the results are being processed
func (t SSHHostKeyHostProcessor) Prepare() {

}

// Finish is called after the results have been processed
func (t SSHHostKeyHostProcessor) Finish() {
	if ok := t.hostFh.Close(); ok != nil {
		log.WithFields(log.Fields{
			"file": t.hostFh.Name(),
		}).Error("Error closing host file")
	}
	if ok := t.keyFh.Close(); ok != nil {
		log.WithFields(log.Fields{
			"file": t.keyFh.Name(),
		}).Error("Error closing host key file")
	}
	if ok := t.relFh.Close(); ok != nil {
		log.WithFields(log.Fields{
			"file": t.relFh.Name(),
		}).Error("Error closing hostKey-host relationship file")
	}
}

// ProcessResult dumps the hostKey
func (t SSHHostKeyHostProcessor) ProcessResult(hIn *Target) {
	// Cast to correct target type
	h, ok := (*hIn).(*SSHTarget)
	if !ok {
		log.Fatal("Did not pass SSHTarget to ProcessResult()")
	}
	// Dump host keys
	err := h.Dump(t.hostFh, t.keyFh, t.relFh, t.timeDiff, t.hostKeyCache, t.skipErrors)
	if err != nil {
		log.WithFields(log.Fields{
			"host file":                      t.hostFh.Name(),
			"certificate file":               t.keyFh.Name(),
			"hostKey-host relationship file": t.relFh.Name(),
		}).Error("Error dumping hostKey", err)
	}
}
