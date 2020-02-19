package scanner

import (
	"crypto/sha1"
	"crypto/sha256"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/bt51/ntpclient"
)

// getSHA1 returns the SHA1 hash of a string
func getSHA1(input []byte) []byte {
	hash := sha1.Sum(input)
	return hash[:]
}

// getSHA256 returns the SHA-256 hash of a string
func getSHA256(input []byte) []byte {
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
func opensslFormat(input string, header string, trailer string) string {
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
func getNtpLocalTimeDiff() (d time.Duration) {
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
func addDefaultPort(input string, defaultPort int) string {
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
