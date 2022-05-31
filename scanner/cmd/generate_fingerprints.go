package cmd

import (
	"encoding/csv"
	"fmt"
	"github.com/rs/zerolog/log"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
)

type GenerateFingerprintsCommand struct {
	GoscannerDir     string `long:"scanner-dir" short:"d" description:"Directory containing a Goscanner scan"`
	CHDir            string `long:"ch-dir" short:"c" description:"Directory containing the Client Hellos used for fingerprinting"`
	KeepStatsRequest bool   `long:"keep-sr" short:"k" description:"Do not remove the Status Request extension from the fingerprint"`
	TempDir          string `long:"tmp-dir" short:"T" description:"Temporary directory for sorting"`
}

func (command *GenerateFingerprintsCommand) Execute(args []string) error {
	return nil
}

func (command GenerateFingerprintsCommand) generateOutput(input chan [][]string, clientHellos []string, output string, lock *sync.WaitGroup) {
	fh, err := os.Create(output)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating fingerprint file")
	}
	defer fh.Close()
	outWriter := csv.NewWriter(fh)
	ch_map := make(map[string]interface{}, len(clientHellos))
	for _, c := range clientHellos {
		ch_map[c] = nil
	}
	sort.Strings(clientHellos)
	err = outWriter.Write(append(append([]string{"ip", "port", "server_name"}, clientHellos...), "fingerprint"))
	if err != nil {
		log.Fatal().Err(err).Msg("Error writing header")
	}
	re_a, err := regexp.Compile("-5\\.")
	if err != nil {
		log.Fatal().Err(err).Msg("Error compiling regex")
	}
	re_b, err := regexp.Compile("_5\\.-?")
	if err != nil {
		log.Fatal().Err(err).Msg("Error compiling regex")
	}
serverLoop:
	for serverRecords := range input {
		var server []string
		fingerprints := make(map[string]string, len(clientHellos))
		for _, scan := range serverRecords {
			if len(scan) < 5 {
				log.Fatal().Strs("Row", scan).Msg("Not enough columns")
			}
			if server == nil {
				server = scan[:3]
			}
			ch := strings.TrimSuffix(scan[3], ".json")
			fp := scan[4]
			if _, ok := ch_map[ch]; ok {
				fingerprints[ch] = fp
			}
		}
		// Write output
		var combined []string
		for _, c := range clientHellos {
			fp, ok := fingerprints[c]
			if ok && fp != "" {
				fp_c := fp
				if !command.KeepStatsRequest {
					fp_c = re_a.ReplaceAllString(fp, "")
					fp_c = re_b.ReplaceAllString(fp_c, "_")
				}
				server = append(server, fp)
				combined = append(combined, fp_c)
			} else {
				continue serverLoop
			}
		}
		server = append(server, strings.Join(combined, "|"))
		err := outWriter.Write(server)
		if err != nil {
			log.Fatal().Err(err).Msg("Could not write fingerprint")
		}
	}
	outWriter.Flush()
	lock.Done()
}

func (command *GenerateFingerprintsCommand) Run() error {

	sortCmd := "sort"
	joinCmd := "join"
	if runtime.GOOS == "darwin" {
		sortCmd = "gsort"
		joinCmd = "gjoin"
	}

	for _, c := range []string{"csvcut", sortCmd, joinCmd} {
		subCommand := exec.Command(c, "--version")
		err := subCommand.Run()
		if err != nil {
			log.Fatal().Err(err).Str("Unknown Command", c).Msg("This command needs csvkit and basic file utils. Install with `pip install csvkit`")
		}
	}

	sortCmd = fmt.Sprintf(`%s -S 10%%`, sortCmd)

	var clientHellos []string
	if command.CHDir != "" {
		files, err := ioutil.ReadDir(command.CHDir)
		if err != nil {
			log.Fatal().Err(err).Msg("Could not read directory content")
		}

		for _, f := range files {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".json") {
				chName := strings.TrimSuffix(f.Name(), ".json")
				clientHellos = append(clientHellos, chName)
			}
		}
	}

	verboseFile := path.Join(command.GoscannerDir, "tls_verbose.csv")
	hostsFile := path.Join(command.GoscannerDir, "hosts.csv")
	fingerprintFile := path.Join(command.GoscannerDir, "fingerprints.csv")
	fingerprintTmpFile := path.Join(command.GoscannerDir, "fingerprints.csv.tmp")

	tmpDir := ""
	if command.TempDir != "" {
		tmpDir = fmt.Sprintf("-T %s", command.TempDir)
		sortCmd = fmt.Sprintf("%s %s", sortCmd, tmpDir)
	}

	if len(clientHellos) == 0 {
		log.Info().Msg("No Client Hellos defined, using all found in the scan for fingerprinting")
		parsingCommand := fmt.Sprintf(`csvcut -p "\\" -c 'client_hello' %s | tail -n+2 | %s -u`, hostsFile, sortCmd)
		log.Debug().Str("Command", parsingCommand).Msg("Collecting used client hellos")
		subCommand := exec.Command("bash", "-c", parsingCommand)
		subCommand.Stderr = os.Stderr
		output, err := subCommand.Output()
		if err != nil {
			log.Fatal().Err(err).Msg("Could not run csvkit")
		}
		clientHellosString := string(output)
		for _, ch := range strings.Split(clientHellosString, "\n") {
			if ch != "" {
				clientHellos = append(clientHellos, strings.TrimSuffix(ch, ".json"))
			}
		}
	}

	hostsSortedFile := path.Join(command.GoscannerDir, "hosts.csv.tmp.sorted")
	verboseSortedFile := path.Join(command.GoscannerDir, "tls_verbose.csv.tmp.sorted")

	prepOneHeader := fmt.Sprintf(`echo "id,ip,port,server_name,client_hello" > %s`, hostsSortedFile)
	command.runCmd(prepOneHeader)
	prepOne := fmt.Sprintf(`csvcut -p \\ -c "id,ip,port,server_name,client_hello" %s | tail -n+2 | %s -t , -b -g -k 1 >> %s`, hostsFile, sortCmd, hostsSortedFile)
	command.runCmd(prepOne)
	defer os.Remove(hostsSortedFile)
	prepTwoHeader := fmt.Sprintf(`echo "id,fingerprint" > %s`, verboseSortedFile)
	command.runCmd(prepTwoHeader)
	prepTwo := fmt.Sprintf(`csvcut -p \\ -c "id,fingerprint" %s | tail -n+2 | %s -t , -b -g -k 1 >> %s`, verboseFile, sortCmd, verboseSortedFile)
	command.runCmd(prepTwo)
	defer os.Remove(verboseSortedFile)

	mergeCommand := fmt.Sprintf(`%s --nocheck-order -t , -j 1 --header %s %s | csvcut -c "ip,port,server_name,client_hello,fingerprint" - | tail -n+2 | %s > %s`, joinCmd, hostsSortedFile, verboseSortedFile, sortCmd, fingerprintTmpFile)
	command.runCmd(mergeCommand)
	defer os.Remove(fingerprintTmpFile)

	processOutput := make(chan [][]string, 100)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go command.generateOutput(processOutput, clientHellos, fingerprintFile, &wg)

	fingerprintTmpFh, err := os.Open(fingerprintTmpFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Error opening sorted fingerprint file")
	}
	defer fingerprintTmpFh.Close()
	csvReader := csv.NewReader(fingerprintTmpFh)
	var lastServer []string
	var currentServerData [][]string
	for {
		records, err := csvReader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal().Err(err).Msg("Error Reading in CSV")
		}
		if len(lastServer) == 0 {
			lastServer = records[:3]
		} else {
			for i, r := range records[:3] {
				if lastServer[i] != r {
					processOutput <- currentServerData
					lastServer = records[:3]
					currentServerData = make([][]string, 0)
					break
				}
			}
		}
		currentServerData = append(currentServerData, records)
	}
	processOutput <- currentServerData

	close(processOutput)
	wg.Wait()

	return nil
}

func (command *GenerateFingerprintsCommand) runCmd(bashCmd string) {
	log.Debug().Str("Command", bashCmd).Msg("Running Command")
	subCommand := exec.Command("bash", "-c", bashCmd)
	subCommand.Stderr = os.Stderr
	subCommand.Stdout = os.Stdout
	err := subCommand.Run()
	if err != nil {
		log.Fatal().Err(err).Msg("Could not run csvkit")
	}
}
