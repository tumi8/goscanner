package scanner

import (
	"encoding/json"
	"errors"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"strconv"
	"strings"
)

// same means that the certificate did not change
const same = "same"

// different means that the certificate changed
const different = "different"

// closed means that an error occurred
const closed = "closed"

// SubmoasInput is one JSON object read from the input file
type SubmoasInput struct {
	Least   string   `json:"least"`
	LeastO  []int    `json:"least_o"`
	Most    string   `json:"most"`
	MostO   []int    `json:"most_o"`
	Targets []string `json:"targets"`
}

// SubmoasTarget is the result of the scanning procedure
type SubmoasTarget struct {
	Timestamp string `json:"scanEnd"`
	Result    string `json:"result"`
}

// SubmoasOutput is one JSON object which will be written to the output file
type SubmoasOutput struct {
	Least   string                   `json:"least"`
	LeastO  []int                    `json:"least_o"`
	Most    string                   `json:"most"`
	MostO   []int                    `json:"most_o"`
	Targets map[string]SubmoasTarget `json:"targets"`
}

// Unmarshal returns the SubmoasInput when passing the bytes read from a file
func Unmarshal(input []byte) ([]SubmoasInput, error) {
	var submoas []SubmoasInput

	err := json.Unmarshal(input, &submoas)

	if err != nil {
		return nil, err
	}
	return submoas, nil
}

// CreateSubmoasOutput returns the SubmoasOutput for an input string and IP address-ScanResult pairs
func CreateSubmoasOutput(input string, res *[]*results.ScanResult) ([]byte, error) {
	submoasInputs, err := Unmarshal([]byte(input))
	if err != nil {
		return nil, err
	}

	// Only one SubmoasInput will be returned for one target
	in := submoasInputs[0]

	// Create SubmoasOutput
	out := SubmoasOutput{in.Least, in.LeastO, in.Most, in.MostO, make(map[string]SubmoasTarget)}

	// Set result for all scanned hosts
	for _, result := range *res {
		for _, subResult := range result.SubResults {
			address := result.Address
			var scanResult string

			// res is nil -> certificate changed
			if subResult.Result == nil {
				scanResult = different
			} else if _, ok := subResult.Result.(error); ok { // res is error -> error occurred, scan not successful
				scanResult = closed
			} else if _, ok := subResult.Result.(*results.CertResult); ok { // res is *[]x509.Certificate -> certificate unchanged
				scanResult = same
			} else { // This should not be reached!
				err = errors.New("error occurred when trying to get result for JSON output")
				return nil, err
			}

			// Set scan result, remove port number
			out.Targets[address[:strings.Index(address, ":")]] = SubmoasTarget{strconv.FormatInt(subResult.ScanEnd.Unix(), 10), scanResult}
		}

	}

	marshalled, err := misc.Marshal([]SubmoasOutput{out})
	if err != nil {
		return nil, err
	}

	return marshalled, nil
}
