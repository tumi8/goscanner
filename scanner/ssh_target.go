package scanner

import (
	"encoding/base64"
	"encoding/csv"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type SSHTarget struct {
	Target
	input     string
	results   map[string]*ScanResult
	fileMutex sync.Mutex
}

// NewSSHTarget returns a pointer to a new SSHTarget struct
func NewSSHTarget(input string) Target {
	h := SSHTarget{}
	h.input = input
	h.results = make(map[string]*ScanResult)

	return &h
}

// IPs returns a slice of IPs for this SSH target
func (h *SSHTarget) IPs() []string {
	// Add port 22 if no port is specified
	return []string{addDefaultPort(h.input, 22)}
}

// Domains returns a slice with an empty string, SNI is not implemented
// this function only exists to match the Target interface
func (h *SSHTarget) Domains() []string {
	log.Fatal("SSH doesn't have domains - this function should not be called")
	return []string{""}
}

// Results returns the result for this SSH host
func (h *SSHTarget) Results() map[string]*ScanResult {
	return h.results
}

// AddResult sets the result for this SSH host
func (h *SSHTarget) AddResult(address string, res *ScanResult) {
	h.results[address] = res
}

// Dump writes the retrieved certificates to a csv file
func (h *SSHTarget) Dump(hostFh, hostKeyFh, relFh *os.File, timediff time.Duration, hostKeyCache map[string]bool, skipErrors bool) error {

	// Create CSV file instances
	hostCsv := csv.NewWriter(hostFh)
	hostKeyCsv := csv.NewWriter(hostKeyFh)
	relCsv := csv.NewWriter(relFh)

	// Call flush in order to write the changes to the files
	defer hostCsv.Flush()
	defer hostKeyCsv.Flush()
	defer relCsv.Flush()

	// Writing to files is not threadsafe
	h.fileMutex.Lock()
	defer h.fileMutex.Unlock()

	for address, res := range h.results {

		// IP and port of the target host
		ip, port, err := net.SplitHostPort(address)
		if err != nil {
			log.WithFields(log.Fields{
				"address": address,
			}).Error("Could not split address into host and port parts.")
		}
		handshakeError := errors.New("")
		var formattedError string

		// Try to convert the res in a SSHResult
		sshRes, ok := res.result.(SSHResult)
		if !ok || sshRes.err != nil {
			if !ok {
				// Try to convert the res in an error value
				handshakeError, ok = res.result.(error)
				if !ok || handshakeError == nil {
					// unknown error, continue with next host
					continue
				}
			} else {
				handshakeError = sshRes.err
			}

			formattedError = handshakeErrorLookup(handshakeError)

		}

		// The following error messages are deemed not important and are therefore not saved
		skip := false
		if skipErrors && formattedError != "" {
			for _, e := range skippedErrors {
				if formattedError == e {
					skip = true
				}
			}
		}
		if skip {
			continue
		}

		if sshRes.fingerprint != "" {
			// Check if host key was already written out before
			// Use byte string as map key to save memory (slices can not be used as map key)
			if !hostKeyCache[sshRes.fingerprint] {
				// Write row in hostKey CSV file
				// [hostKey, fingerprint]
				hostKeyString := base64.StdEncoding.EncodeToString(sshRes.hostKey.Marshal())
				if ok := hostKeyCsv.Write([]string{hostKeyString, sshRes.fingerprint}); ok != nil {
					log.WithFields(log.Fields{
						"file": hostKeyFh.Name(),
					}).Error("Error writing to host key to file")
				} else {
					hostKeyCache[sshRes.fingerprint] = true
				}
			}

			// Write to hostKey-host relation CSV file
			// [fingerprint, host, port]
			if ok := relCsv.Write([]string{sshRes.fingerprint, ip, port}); ok != nil {
				log.WithFields(log.Fields{
					"file": relFh.Name(),
				}).Error("Error writing to hostKey-host-relationship file")
			}
		}

		var scanEndStr string
		if res.scanEnd.Unix() > 0 {
			scanEndStr = strconv.FormatInt(res.scanEnd.Add(timediff).Unix(), 10)
		}

		// Write row in host CSV file
		// [host, port, synStart, synEnd, scanEnd, ssh_version, server_version, serverHostKeyAlgos, ciphersServerClient, ciphersClientServer, macsServerClient, macsClientServer, error_data]

		if ok := hostCsv.Write([]string{ip, port, strconv.FormatInt(res.synStart.Add(timediff).Unix(), 10), strconv.FormatInt(res.synEnd.Add(timediff).Unix(), 10), scanEndStr, sshRes.sshVersion, sshRes.serverVersion, strings.Join(sshRes.serverHostKeyAlgos, ";"), strings.Join(sshRes.ciphersServerClient, ";"), strings.Join(sshRes.ciphersClientServer, ";"), strings.Join(sshRes.macsServerClient, ";"), strings.Join(sshRes.macsClientServer, ";"), strings.Join(sshRes.kexAlgos, ";"), strings.Join(sshRes.languagesServerClient, ";"), strings.Join(sshRes.languagesClientServer, ";"), strings.Join(sshRes.compressionsServerClient, ";"), strings.Join(sshRes.compressionsClientServer, ";"), handshakeError.Error()}); ok != nil {
			log.WithFields(log.Fields{
				"file": hostFh.Name(),
			}).Error("Error writing to host file")
		}

	}

	// No error encountered
	return nil
}
