package scanner

import (
	"bufio"
	"bytes"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/scans"
	"io"
	"io/ioutil"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/tumi8/goscanner/scanner/asset"
)

// ReadIPsFromTxt reads IP addresses separated by newlines from an input file and sends them to the channel
func ReadIPsFromTxt(filename string, targetChan chan *scans.TargetBatch) {
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
		line := fileScanner.Text()
		target := scans.Target{}
		split := strings.Split(line, ",")
		target.Ip = split[0]
		if len(split) == 2 {
			// Make sure to remove trailing dots in domain names: google.com. -> google.com
			target.Domain = strings.TrimRight(split[1], ".")
		} else if len(split) > 2 {
			log.WithFields(log.Fields{
				"input": line,
			}).Error("Got input line with more than two fields.")
		}
		var targetBatch scans.TargetBatch
		targetBatch = target
		targetChan <- &targetBatch
	}
}

// ReadTargetsFromJSON reads targets from a JSON input file and sends them to the channel
func ReadSubmoaTargetsFromJSON(filename string, targetChan chan *scans.TargetBatch) {
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
		input, err := misc.Marshal([]SubmoasInput{submoas})
		if err != nil {
			log.Fatal("Error marshalling input JSON")
		}
		json, err := Unmarshal(input)
		targets := scans.SubmoaTarget{Json: json[0]}
		if err != nil {
			log.Fatal("Error unmarshalling input for target")
		}
		targets.Targets_ = make([]scans.Target, len(json[0].Targets))
		for i, ip := range json[0].Targets {
			targets.Targets_[i].Ip = ip
			targets.Targets_[i].Domain = ""
		}
		var batchTarget scans.TargetBatch
		batchTarget = targets
		targetChan <- &batchTarget
	}
}

// GenerateTargetsFromSeed generates target IPs using a seeded LCG and sends them to the channnel
func GenerateTargetsFromSeed(seed string, increment, offset int64, targetChan chan *scans.TargetBatch) {
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
		var h scans.TargetBatch
		h = scans.Target{Ip: input.String(), Domain: ""}
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
