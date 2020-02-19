package scanner

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/tumi8/goscanner/scanner/asset"
	"github.com/tumi8/tls"
)

// ReadIPsFromTxt reads IP addresses separated by newlines from an input file and sends them to the channel
func ReadIPsFromTxt(filename string, targetChan chan *Target, newTarget func(string) Target) {
	// Close channel when all IPs have been sent
	defer close(targetChan)

	fh, err := os.Open(filename)
	if err != nil {
		log.WithFields(log.Fields{
			"file": filename,
		}).Fatal(err)
	}
	defer fh.Close()

	reader := bufio.NewReader(fh)
	fileScanner := bufio.NewScanner(reader)

	for fileScanner.Scan() {
		h := newTarget(fileScanner.Text())
		targetChan <- &h
	}
}

// ReadTargetsFromJSON reads targets from a JSON input file and sends them to the channel
func ReadTargetsFromJSON(filename string, targetChan chan *Target, newTarget func(string) Target) {
	// Close channel when all input has been sent
	defer close(targetChan)

	json, err := ioutil.ReadFile(filename)
	if err != nil {
		log.WithFields(log.Fields{
			"file": filename,
		}).Fatal(err)
	}

	// Create objects from input JSON
	submoases, err := Unmarshal(json)
	if err != nil {
		log.Fatal("Error unmarshalling input JSON")
	}

	// Convert back to JSON and send to targetChan
	for _, submoas := range submoases {
		input, err := Marshal([]SubmoasInput{submoas})
		if err != nil {
			log.Fatal("Error marshalling input JSON")
		}
		h := newTarget(string(input))
		targetChan <- &h
	}
}

// GenerateTargetsFromSeed generates target IPs using a seeded LCG and sends them to the channnel
func GenerateTargetsFromSeed(seed string, increment, offset int64, targetChan chan *Target, newTarget func(string) Target) {
	// Close channel when all input has been sent
	defer close(targetChan)

	ipgenerator := NewIPProvider(seed, increment, offset)

	// Generate IPs and send them to the channel
	for {
		input, err := ipgenerator.GenerateNextRandomIP()

		if err != nil {
			log.WithFields(log.Fields{
				"lastIP": input,
			}).Error(err)
			break
		}
		h := newTarget(input.String())
		targetChan <- &h
	}
}

// ReadGitVersionFromAsset reads current git version hash
func ReadGitVersionFromAsset() string {

	const gitVersionAssetName = "git-version"

	data, err := asset.Asset(gitVersionAssetName)
	if err != nil {
		log.WithFields(log.Fields{
			"assetName": gitVersionAssetName,
		}).Fatal("Asset not found")
	}
	reader := bufio.NewReader(bytes.NewBuffer(data))
	fileScanner := bufio.NewScanner(reader)

	fileScanner.Scan()
	gitVersion := fileScanner.Text()

	return gitVersion
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

	return cipherSuites
}

// LineCounter returns the number of lines in a file
// Adapted from:
// http://stackoverflow.com/questions/24562942/golang-how-do-i-determine-the-number-of-lines-in-a-file-efficiently
func LineCounter(filename string) (int64, error) {

	fh, err := os.Open(filename)
	if err != nil {
		return 0, err
	}

	buf := make([]byte, 32*1024)
	var count int64
	lineSep := []byte{'\n'}

	for {
		c, err := fh.Read(buf)
		count += int64(bytes.Count(buf[:c], lineSep))

		switch {
		case err == io.EOF:
			return count, nil

		case err != nil:
			return count, err
		}
	}
}
