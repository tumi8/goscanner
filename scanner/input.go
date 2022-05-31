package scanner

import (
	"bufio"
	"bytes"
	"github.com/DataDog/zstd"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/scans"
	"io"
	"os"
	"strings"
)

// ReadIPsFromTxt reads IP addresses separated by newlines from an input file and sends them to the channel
func ReadTargetsToChannel(opts misc.Options, targetChan chan *scans.Target) {
	// Close channel when all IPs have been sent
	defer close(targetChan)
	filename := opts.Input

	var fh *os.File
	if filename == "-" {
		log.Info().Msg("Reading input from Stdin")
		fh = os.Stdin
	} else if filename != "" {
		var err error
		fh, err = os.Open(filename)
		if err != nil {
			log.Fatal().Err(err).Str("file", filename).Msg("Error opening file")
		}
		defer fh.Close()
	}

	var reader io.Reader
	if strings.HasSuffix(filename, ".zst") {
		reader = zstd.NewReader(fh)
	} else {
		reader = bufio.NewReader(fh)
	}
	fileScanner := bufio.NewScanner(reader)

	for fileScanner.Scan() {
		line := fileScanner.Text()
		target := scans.Target{}
		split := strings.Split(line, ",")
		target.Ip = split[0]
		if len(split) > 3 {
			log.Error().Str("input", line).Msg("Got input line with more than three fields.")
		}
		if len(split) >= 2 {
			// Make sure to remove trailing dots in domain names: google.com. -> google.com
			target.Domain = strings.TrimRight(split[1], ".")
		}
		chName := ""
		if len(split) >= 3 {
			chName = split[2]
		}
		target.CHName = chName

		targetChan <- &target
	}
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
