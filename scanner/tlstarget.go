package scanner

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
)

// beginCertificate and endCertificate signal start and beginning of PEM-encoded TLS certificates
const beginCertificate = "-----BEGIN CERTIFICATE-----"
const endCertificate = "-----END CERTIFICATE-----"

// skippedErrors defines the errors which will *NOT* be written to hosts.csv if the option is specified on the command line
var skippedErrors = [...]string{"TIMEOUT", "CONNECTION REFUSED", "NO ROUTE", "NETWORK UNREACHABLE"}

// TLSTarget contains a single TLS host to be scanned
type TLSTarget struct {
	Target
	input   string
	results map[string]*ScanResult
}

// NewTLSTarget returns a pointer to a new TLSTarget struct
func NewTLSTarget(input string) Target {
	h := TLSTarget{}
	h.input = input
	h.results = make(map[string]*ScanResult)
	return &h
}

// IPs returns a slice of IPs for this TLS target
func (h *TLSTarget) IPs() []string {
	// Add port 443 if no port is specified
	return []string{addDefaultPort(h.input, 443)}
}

// Domains returns a slice with an empty string, SNI is not implemented
func (h *TLSTarget) Domains() []string {
	return []string{""}
}

// Results returns the result for this TLS host
func (h *TLSTarget) Results() map[string]*ScanResult {
	return h.results
}

// AddResult sets the result for this TLS host
func (h *TLSTarget) AddResult(address string, res *ScanResult) {
	h.results[address] = res
}

// DumpTLSTarget contains a single TLS target whose result can be dumped
type DumpTLSTarget struct {
	Target
	DumpableTarget
	input   string
	results map[string]*ScanResult
	mutex   sync.Mutex
}

// IPs returns a slice of IPs for this TLS target
func (h *DumpTLSTarget) IPs() []string {
	// Add port 443 if no port is specified
	return []string{addDefaultPort(h.input, 443)}
}

// Domains returns a slice with one empty string, SNI is not implemented.
func (h *DumpTLSTarget) Domains() []string {
	return []string{""}
}

// Results returns the result for this TLS host
func (h *DumpTLSTarget) Results() map[string]*ScanResult {
	return h.results
}

// AddResult sets the result for this TLS host
func (h *DumpTLSTarget) AddResult(address string, res *ScanResult) {
	// Maps are not thread-safe
	h.mutex.Lock()
	h.results[address] = res
	h.mutex.Unlock()
}

// NewDumpTLSTarget returns a pointer to a new DumpTLSTarget struct
func NewDumpTLSTarget(input string) Target {
	h := DumpTLSTarget{}
	h.input = input
	h.results = make(map[string]*ScanResult)
	return &h
}

// Dump writes the retrieved certificates to a directory
func (h *DumpTLSTarget) Dump(baseDir string) error {
	os.MkdirAll(baseDir, 0755)
	for address, res := range h.results {

		// Try to convert the result in a TLSResult
		tlsRes, ok := res.result.(TLSResult)
		if !ok || tlsRes.err != nil {
			// Do not dump scanning errors
			continue
		}

		for i, cert := range tlsRes.certificates {

			// The resulting filename is the base directory concatenated with the IP address, the Unix timestamp and the number of certificate in the chain
			filename := filepath.Join(baseDir, address+"-"+strconv.FormatInt(res.scanEnd.Unix(), 10)+"-"+strconv.Itoa(i)+".der")

			// Create a new file for the cert dump, returns an error if it already exists
			fh, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if err != nil {
				return err
			}
			defer fh.Close()

			// Dump raw DER-encoded certificate
			fh.Write(cert.Raw)
		}
	}

	// No error encountered
	return nil
}

// MultiTLSTarget contains multiple TLS hosts to be scanned
type MultiTLSTarget struct {
	Target
	DumpableTarget
	JSONableTarget
	input   string
	json    SubmoasInput
	results map[string]*ScanResult
	mutex   sync.Mutex
}

// NewMultiTLSTarget returns a pointer to a TLS target with multiple hosts
func NewMultiTLSTarget(input string) Target {
	h := MultiTLSTarget{}
	h.input = input
	json, err := Unmarshal([]byte(input))
	if err != nil {
		log.Fatal("Error unmarshalling input for target")
	}
	// One SubmoasInput per target
	h.json = json[0]
	h.results = make(map[string]*ScanResult)
	return &h
}

// IPs returns a list of TLS IPs to be scanned
func (h *MultiTLSTarget) IPs() []string {
	ret := []string{}
	for _, ip := range h.json.Targets {
		// Add port 443 if no port is specified
		ret = append(ret, addDefaultPort(ip, 443))
	}
	return ret
}

// Domains returns a slice with empty strings, SNI is not implemented.
func (h *MultiTLSTarget) Domains() []string {
	ret := []string{}
	for _ = range h.json.Targets {
		ret = append(ret, "")
	}
	return ret
}

// Results returns the results for all scanned hosts of this TLS host
func (h *MultiTLSTarget) Results() map[string]*ScanResult {
	return h.results
}

// AddResult appends one host result to this TLS target
func (h *MultiTLSTarget) AddResult(address string, res *ScanResult) {
	// Maps are not thread-safe
	h.mutex.Lock()
	h.results[address] = res
	h.mutex.Unlock()
}

// Dump writes the retrieved certificates to a directory
func (h *MultiTLSTarget) Dump(baseDir string) error {
	os.MkdirAll(baseDir, 0755)
	for address, res := range h.results {

		// Try to convert the result in a slice of certificates
		certs, ok := res.result.([]*x509.Certificate)
		if !ok {
			// Do not dump scanning errors
			continue
		}

		for i, cert := range certs {

			// The resulting filename is the base directory concatenated with the IP address, the Unix timestamp and the number of certificate in the chain
			filename := filepath.Join(baseDir, address+"-"+strconv.FormatInt(res.scanEnd.Unix(), 10)+"-"+strconv.Itoa(i)+".der")

			// Create a new file for the cert dump, returns an error if it already exists
			fh, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if err != nil {
				return err
			}
			defer fh.Close()

			// Dump raw DER-encoded certificate
			fh.Write(cert.Raw)
		}
	}

	// No error encountered
	return nil
}

// JSON returns a JSON encoding for this target
func (h *MultiTLSTarget) JSON() ([]byte, error) {
	out, err := CreateSubmoasOutput(h.input, h.results)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// CertHostTLSTarget contains multiple TLS hosts to be scanned
type CertHostTLSTarget struct {
	Target
	ip          string
	domain      string
	results     map[string][]*ScanResult
	resultMutex sync.Mutex
	fileMutex   sync.Mutex
}

// NewCertHostTLSTarget returns a pointer to a TLS target with multiple hosts
func NewCertHostTLSTarget(input string) Target {
	h := CertHostTLSTarget{}

	split := strings.Split(input, ",")
	h.ip = split[0]
	if len(split) == 2 {
		// Make sure to remove trailing dots in domain names: google.com. -> google.com
		h.domain = strings.TrimRight(split[1], ".")
	} else if len(split) > 2 {
		log.WithFields(log.Fields{
			"input": input,
		}).Error("Got input line with more than two fields.")
	}

	h.results = make(map[string][]*ScanResult)
	return &h
}

// IPs returns a slice of IPs for this TLS target
func (h *CertHostTLSTarget) IPs() []string {
	// Add port 443 if no port is specified
	return []string{addDefaultPort(h.ip, 443)}
}

// Domains returns a slice with one domain string, SNI is enabled
func (h *CertHostTLSTarget) Domains() []string {
	return []string{h.domain}
}

// Results returns the results for all scanned hosts of this TLS host
func (h *CertHostTLSTarget) Results() map[string]*ScanResult {
	panic("Not implemented")
}

// AddResult appends one host result to this TLS target
func (h *CertHostTLSTarget) AddResult(address string, res *ScanResult) {
	// Maps are not thread-safe
	h.resultMutex.Lock()
	curr := h.results[address]
	h.results[address] = append(curr, res)
	h.resultMutex.Unlock()
}

// Dump writes the retrieved certificates to a csv file
func (h *CertHostTLSTarget) Dump(hostFh, certFh, chrFh, scsvFh, httpFh *os.File, timediff time.Duration, certCache map[string]bool, cipherSuites map[uint16]string, skipErrors bool, cacheFunc func([]byte) []byte) error {

	// Create CSV file instances
	hostCsv := csv.NewWriter(hostFh)
	certCsv := csv.NewWriter(certFh)
	chrCsv := csv.NewWriter(chrFh)

	// Call flush in order to write the changes to the files
	defer hostCsv.Flush()
	defer certCsv.Flush()
	defer chrCsv.Flush()

	// Writing to files is not threadsafe
	h.fileMutex.Lock()
	defer h.fileMutex.Unlock()

	for address, results := range h.results {

		// Multiple results for one address (e.g. normal + SCSV)
		for _, res := range results {

			// IP and port of the target host
			ip, port, err := net.SplitHostPort(address)
			if err != nil {
				log.WithFields(log.Fields{
					"address": address,
				}).Error("Could not split address into host and port parts.")
			}

			resultString := "SUCCESS"
			handshakeError := errors.New("")
			var protocol string
			var cipher string

			// Try to convert the result in a TLSResult
			tlsRes, ok := res.result.(TLSResult)
			if !ok {
				scsvRes, ok := res.result.(SCSVResult)
				if ok {
					scsvCsv := csv.NewWriter(scsvFh)
					defer scsvCsv.Flush()

					// Check protocol and cipher
					if protocol, ok = cipherSuites[tlsRes.version]; !ok {
						protocol = "not set"
					}
					if cipher, ok = cipherSuites[tlsRes.cipher]; !ok {
						cipher = "not set"
					}

					if ok := scsvCsv.Write([]string{ip, port, h.domain, strconv.FormatInt(res.synStart.Add(timediff).Unix(), 10), strconv.FormatInt(res.synEnd.Add(timediff).Unix(), 10), strconv.FormatInt(res.scanEnd.Add(timediff).Unix(), 10), protocol, cipher, scsvRes.err.Error()}); ok != nil {
						log.WithFields(log.Fields{
							"file": scsvFh.Name(),
						}).Error("Error writing to SCSV file")
					}
					continue
				} else {

					// Try to convert the result in an HTTPResult
					httpRes, ok := res.result.(HTTPResult)
					if ok {
						// Write row in HTTP CSV file
						// [host, port, server_name, http_method, http_path, http_code, http_headers
						httpCsv := csv.NewWriter(httpFh)
						defer httpCsv.Flush()
						errorStr := ""
						if httpRes.httpError != nil {
							errorStr = httpRes.httpError.Error()
						}
						if ok := httpCsv.Write([]string{ip, port, h.domain, httpRes.httpMethod, httpRes.httpPath, strconv.Itoa(httpRes.httpCode), httpRes.httpHeaders, errorStr}); ok != nil {
							log.WithFields(log.Fields{
								"file": httpFh.Name(),
							}).Error("Error writing to HTTP file")
						}

						continue
					} else {

						// Try to convert the result in an error value
						handshakeError, ok = res.result.(error)
						if !ok || handshakeError == nil {
							// unknown error, continue with next host
							continue
						}
						resultString = handshakeErrorLookup(handshakeError)
					}
				}
			}

			// Check protocol and cipher
			if protocol, ok = cipherSuites[tlsRes.version]; !ok {
				protocol = "not set"
			}
			if cipher, ok = cipherSuites[tlsRes.cipher]; !ok {
				cipher = "not set"
			}

			// The following error messages are deemed not important and are therefore not saved
			skip := false
			if skipErrors {
				for _, e := range skippedErrors {
					if resultString == e {
						skip = true
					}
				}
			}
			if skip {
				continue
			}

			for i, cert := range tlsRes.certificates {
				hashBytes := cacheFunc(cert.Raw)
				hashHex := hex.EncodeToString(hashBytes)

				// Check if certificate was already written out before
				// Use byte string as map key to save memory (slices can not be used as map key)
				if !certCache[string(hashBytes)] {
					// Write row in cert CSV file
					// [cert, cert_hash]
					certString := opensslFormat(base64.StdEncoding.EncodeToString(cert.Raw), beginCertificate, endCertificate)
					if ok := certCsv.Write([]string{certString, hashHex}); ok != nil {
						log.WithFields(log.Fields{
							"file": certFh.Name(),
						}).Error("Error writing to certificate file")
					} else {
						certCache[string(hashBytes)] = true
					}
				}

				// Write to certificate-host relation CSV file
				// [cert_hash, host, port, depth]
				if ok := chrCsv.Write([]string{hashHex, ip, port, h.domain, strconv.Itoa(i)}); ok != nil {
					log.WithFields(log.Fields{
						"file": chrFh.Name(),
					}).Error("Error writing to host-certificate-relationship file")
				}
			}

			var scanEndStr string
			if res.scanEnd.Unix() > 0 {
				scanEndStr = strconv.FormatInt(res.scanEnd.Add(timediff).Unix(), 10)
			}

			// Write row in host CSV file
			// [host, rtt, port, server_name, synStart, synEnd, scanEnd, protocol, cipher, result, verify_err_no, verify_code, server_version, depth, depth_verbose, error_data]
			if ok := hostCsv.Write([]string{ip, "", port, h.domain, strconv.FormatInt(res.synStart.Add(timediff).Unix(), 10), strconv.FormatInt(res.synEnd.Add(timediff).Unix(), 10), scanEndStr, protocol, cipher, resultString, "", "", "", "", "", handshakeError.Error()}); ok != nil {
				log.WithFields(log.Fields{
					"file": hostFh.Name(),
				}).Error("Error writing to host file")
			}
		}
	}

	// No error encountered
	return nil
}

// handshakeErrorLookup returns a string for a certain handshake error
func handshakeErrorLookup(err error) string {
	handshakeError := err.Error()
	var result string
	if m, _ := regexp.MatchString("timeout", handshakeError); m {
		result = "TIMEOUT"
	} else if m, _ := regexp.MatchString("connection refused", handshakeError); m {
		result = "CONNECTION REFUSED"
	} else if m, _ := regexp.MatchString("connection reset by peer", handshakeError); m {
		result = "CONNECTION RESET BY PEER"
	} else if m, _ := regexp.MatchString("no route to host", handshakeError); m {
		result = "NO ROUTE"
	} else if m, _ := regexp.MatchString("network is unreachable", handshakeError); m {
		result = "NETWORK UNREACHABLE"
	} else if m, _ := regexp.MatchString("unknown protcol", handshakeError); m {
		result = "UNKNOWN PROTOCOL"
	} else if m, _ := regexp.MatchString("protocol version", handshakeError); m {
		result = "UNKNOWN PROTOCOL"
	} else if m, _ := regexp.MatchString("tls: oversized record received with length", handshakeError); m {
		result = "OVERSIZED RECORD"
	} else if m, _ := regexp.MatchString("tls", handshakeError); m {
		result = "SSL HANDSHAKE FAILURE"
	} else if m, _ := regexp.MatchString("handshake failure", handshakeError); m {
		result = "SSL HANDSHAKE FAILURE"
	} else {
		result = "OTHER FAILURE"
	}
	return result
}
