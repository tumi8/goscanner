package misc

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"github.com/tumi8/goscanner/scanner/asset"
	"github.com/tumi8/tls"
	"strconv"
	"strings"
	"time"

	"github.com/bt51/ntpclient"
	log "github.com/sirupsen/logrus"
)

// getSHA1 returns the SHA1 hash of a string
func GetSHA1(input []byte) []byte {
	hash := sha1.Sum(input)
	return hash[:]
}

// getSHA256 returns the SHA-256 hash of a string
func GetSHA256(input []byte) []byte {
	hash := sha256.Sum256(input)
	return hash[:]
}

// min returns the smaller one of two integers
func min(one, two int) int {
	if one < two {
		return one
	}
	return two
}

// opensslFormat adds the PEM beginning and end markers and inserts newlines at the right position
func OpensslFormat(input string, header string, trailer string) string {
	res := ""

	// Newline after 64 characters
	start := 0
	for end := 64; start < len(input)-1; end = min(end+64, len(input)) {
		res += input[start:end] + "\n"
		start = end
	}

	return header + "\n" + res + trailer
}

// getNtpLocalTimeDiff returns the time difference between the system time and ntp.org
func GetNtpLocalTimeDiff() (d time.Duration) {
	t0, err := ntpclient.GetNetworkTime("0.pool.ntp.org", 123)
	if err != nil {
		d = 0
		log.Warn("Get NTP time failed", err)
		return d
	}
	t1 := time.Now().UTC()
	d = t0.Sub(t1)
	return d
}

// addDefaultPort adds a default port if none is present in IPv4 or IPv6 addresses
func AddDefaultPort(input string, defaultPort int) string {
	// IPv6 addresses have at least two colons
	if strings.Count(input, ":") >= 2 {
		// Check if brackets are already there
		if input[:1] != "[" {
			input = "[" + input + "]"
		}
		// Check if port is missing
		if input[len(input)-1:] == "]" {
			input += ":" + strconv.Itoa(defaultPort)
		}
	}

	// IPv4 without port
	if !strings.Contains(input, ":") {
		input += ":" + strconv.Itoa(defaultPort)
	}

	return input
}

// ReadCiphersFromAsset reads TLS cipher suites
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
func ReadCiphersFromAsset() map[uint16]string {
	cipherSuites := make(map[uint16]string)

	const ciphersAssetName = "tls-parameters-4.csv"

	data, err := asset.Asset(ciphersAssetName)
	if err != nil {
		log.WithFields(log.Fields{
			"assetName": ciphersAssetName,
		}).Fatal("Asset not found")
	}
	reader := csv.NewReader(bytes.NewBuffer(data))

	for line, err := reader.Read(); err == nil; line, err = reader.Read() {
		// Line does not contain a cipher
		if len(line) < 2 {
			continue
		}
		verStr := line[0]
		cipher := line[1]

		// 0x00,0x18 --> [0x00 0x18]
		verSplit := strings.Split(verStr, ",")
		if len(verSplit) != 2 {
			continue
		}
		if len(verSplit[0]) != 4 || len(verSplit[1]) != 4 {
			continue
		}

		// [0x00 , 0x18] --> 0x0018
		verStr = verSplit[0] + verSplit[1][2:]
		verUInt64, err := strconv.ParseUint(verStr, 0, 16)
		if err != nil {
			continue
		}
		verUInt16 := uint16(verUInt64)

		if !(strings.HasPrefix(cipher, "TLS")) {
			continue
		}

		cipherSuites[verUInt16] = cipher
	}

	// Add TLS versions
	cipherSuites[tls.VersionSSL30] = `SSLv3`
	cipherSuites[tls.VersionTLS10] = `TLSv1`
	cipherSuites[tls.VersionTLS11] = `TLSv1.1`
	cipherSuites[tls.VersionTLS12] = `TLSv1.2`
	cipherSuites[tls.VersionTLS13] = `TLSv1.3`

	return cipherSuites
}

// Marshal returns the byte array when passing the SubmoasInput structs
func Marshal(output interface{}) ([]byte, error) {
	return json.Marshal(output)
}
