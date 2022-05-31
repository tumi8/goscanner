package cmd

import (
	"bufio"
	"encoding/csv"
	"github.com/rs/zerolog/log"
	"io/ioutil"
	"os"
	"strings"
	"sync"
)

type CreateCHInputCommand struct {
	ChDir string `long:"ch-dir" short:"d" description:"Directory containing all the Client Hellos"`
	Input string `long:"input" short:"i" description:"Input with IP, domain name tuples" default:"-"`
}

func (command *CreateCHInputCommand) Execute(args []string) error {
	return nil
}

func (command CreateCHInputCommand) PrintCHCrossProduct(clientHellos []string, input chan []string, lock *sync.WaitGroup) {
	outWriter := csv.NewWriter(os.Stdout)
	for records := range input {
		for _, ch := range clientHellos {
			err := outWriter.Write(append(records, ch))
			if err != nil {
				log.Fatal().Err(err).Msg("Could not write to output")
			}
		}
	}
	outWriter.Flush()
	lock.Done()
}

func (command *CreateCHInputCommand) Run() error {
	var fh *os.File
	if command.Input == "-" {
		log.Info().Msg("Reading input from Stdin")
		fh = os.Stdin
	} else {
		var err error
		fh, err = os.Open(command.Input)
		if err != nil {
			log.Fatal().Err(err).Str("file", command.Input).Msg("Error opening file")
		}
		defer fh.Close()
	}

	files, err := ioutil.ReadDir(command.ChDir)
	if err != nil {
		log.Fatal().Err(err).Msg("Could not read directory content")
	}

	var clientHellos []string

	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".json") {
			chName := strings.TrimSuffix(f.Name(), ".json")
			clientHellos = append(clientHellos, chName)
		}
	}
	if len(clientHellos) == 0 {
		log.Fatal().Msg("Not Client Hellos specified")
	}
	inputChan := make(chan []string, 100)

	outputLock := sync.WaitGroup{}
	outputLock.Add(1)

	go command.PrintCHCrossProduct(clientHellos, inputChan, &outputLock)

	fileScanner := bufio.NewScanner(fh)

	for fileScanner.Scan() {
		line := fileScanner.Text()
		records := strings.Split(line, ",")
		if len(records) < 2 {
			records = append(records, "")
		}
		inputChan <- records
	}
	close(inputChan)

	outputLock.Wait()
	return nil
}
