package scanner

import (
	"encoding/base64"
	"encoding/csv"
	"errors"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// sshHostCsvHeader represents the header line of the hosts.csv file
var sshHostCsvHeader = []string{"host", "port", "syn_start", "syn_end", "scan_end", "ssh_version", "server_version", "server_host_key_algos", "ciphers_server_client", "ciphers_client_server", "macs_server_client", "macs_client_server", "kex_algos", "languages_server_client", "languages_client_server", "compressions_server_client", "compressions_client_server", "error_data"}

// sshRelationCsvHeader represents the header line of the relations.csv file
var sshRelationCsvHeader = []string{"fingerprint", "host", "port"}

// sshHostKeyCsvHeader represents the header line of the hostKeys.csv file
var sshHostKeyCsvHeader = []string{"host_key", "fingerprint"}

var skippedErrors = [...]string{"TIMEOUT", "CONNECTION REFUSED", "NO ROUTE", "NETWORK UNREACHABLE"}

// SSHHostKeyHostProcessor implements the processing of SSH scanning results
type SSHHostKeyHostProcessor struct {
	Processor
	hostFh       *os.File
	keyFh        *os.File
	relFh        *os.File
	timeDiff     time.Duration
	hostKeyCache map[string]bool
	skipErrors   bool
	fileMutex	 sync.Mutex
}

// NewSSHHostKeyHostProcessor returns a new processor for results of scanned SSH hosts
func NewSSHHostKeyHostProcessor(hostkeyfile, hostfile, relfile string, skipErrors bool) *ResultProcessor {
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

	t.timeDiff = misc.GetNtpLocalTimeDiff()

	t.skipErrors = skipErrors

	var r ResultProcessor
	r = t

	return &r
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
func (t SSHHostKeyHostProcessor) ProcessResult(hIn *results.BatchScanResult) {
	// Dump host keys
	// Writing to files is not threadsafe

	t.fileMutex.Lock()
	defer t.fileMutex.Unlock()
	hostCsv := csv.NewWriter(t.hostFh)
	hostKeyCsv := csv.NewWriter(t.keyFh)
	relCsv := csv.NewWriter(t.relFh)
	defer hostCsv.Flush()
	defer hostKeyCsv.Flush()
	defer relCsv.Flush()
	for _, result := range hIn.Results {
		for _, subResult := range result.SubResults {
			// IP and port of the target host
			ip, port, err := net.SplitHostPort(result.Address)
			if err != nil {
				log.WithFields(log.Fields{
					"address": result.Address,
				}).Error("Could not split address into host and port parts.")
			}
			handshakeError := errors.New("")
			var formattedError string

			// Try to convert the res in a SSHResult
			sshRes, ok := subResult.Result.(*results.SSHResult)
			if !ok || sshRes.Err != nil {
				handshakeError = sshRes.Err

				formattedError = results.HandshakeErrorLookup(handshakeError)

			}

			// The following error messages are deemed not important and are therefore not saved
			skip := false
			if t.skipErrors && formattedError != "" {
				for _, e := range skippedErrors {
					if formattedError == e {
						skip = true
					}
				}
			}
			if skip {
				continue
			}

			if sshRes.Fingerprint != "" {
				// Check if host key was already written out before
				// Use byte string as map key to save memory (slices can not be used as map key)
				if !t.hostKeyCache[sshRes.Fingerprint] {
					// Write row in hostKey CSV file
					// [hostKey, fingerprint]
					hostKeyString := base64.StdEncoding.EncodeToString(sshRes.HostKey.Marshal())
					if ok := hostKeyCsv.Write([]string{hostKeyString, sshRes.Fingerprint}); ok != nil {
						log.WithFields(log.Fields{
							"file": t.hostFh.Name(),
						}).Error("Error writing to host key to file")
					} else {
						t.hostKeyCache[sshRes.Fingerprint] = true
					}
				}

				// Write to hostKey-host relation CSV file
				// [fingerprint, host, port]
				if ok := relCsv.Write([]string{sshRes.Fingerprint, ip, port}); ok != nil {
					log.WithFields(log.Fields{
						"file": t.relFh.Name(),
					}).Error("Error writing to hostKey-host-relationship file")
				}
			}

			var scanEndStr string
			if subResult.ScanEnd.Unix() > 0 {
				scanEndStr = strconv.FormatInt(subResult.ScanEnd.Add(t.timeDiff).Unix(), 10)
			}

			// Write row in host CSV file
			// [host, port, synStart, synEnd, scanEnd, ssh_version, server_version, serverHostKeyAlgos, ciphersServerClient, ciphersClientServer, macsServerClient, macsClientServer, error_data]

			if ok := hostCsv.Write([]string{ip, port, strconv.FormatInt(subResult.SynStart.Add(t.timeDiff).Unix(), 10), strconv.FormatInt(subResult.SynEnd.Add(t.timeDiff).Unix(), 10), scanEndStr, sshRes.SshVersion, sshRes.ServerVersion, strings.Join(sshRes.ServerHostKeyAlgos, ";"), strings.Join(sshRes.CiphersServerClient, ";"), strings.Join(sshRes.CiphersClientServer, ";"), strings.Join(sshRes.MacsServerClient, ";"), strings.Join(sshRes.MacsClientServer, ";"), strings.Join(sshRes.KexAlgos, ";"), strings.Join(sshRes.LanguagesServerClient, ";"), strings.Join(sshRes.LanguagesClientServer, ";"), strings.Join(sshRes.CompressionsServerClient, ";"), strings.Join(sshRes.CompressionsClientServer, ";"), handshakeError.Error()}); ok != nil {
				log.WithFields(log.Fields{
					"file": t.hostFh.Name(),
				}).Error("Error writing to host file")
			}
		}
	}
}
