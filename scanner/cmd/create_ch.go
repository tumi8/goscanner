package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/cmd/createch"
	"github.com/tumi8/goscanner/tls"
	"os"
	"path"
	"path/filepath"
	"strconv"
)

type CreateCHCommand struct {
	ListIDS      bool   `long:"list" short:"l" description:"list all available client hellos"`
	OutDir       string `long:"out" description:"Create all client hellos and save into directory"`
	CreateCHType string `long:"create" short:"c" choice:"jarm" choice:"custom" choice:"random" description:"Generate these Client Hellos"`
	RandomCHs    int    `long:"num-random" description:"Number of Random CHs to generate" default:"100"`
	TmpDir       string `long:"tmp" description:"Temp Direcotry to download IANA parameters for Random CHs"`
}

func (command *CreateCHCommand) Execute(args []string) error {
	return nil
}

type chID struct {
	info  string
	value *tls.ClientHelloPreset
}

// Add clientHello here with a description
var customMap = map[string]chID{
	"chrome70":       chID{"chrome", &createch.Chrome70},
	"chrome83":       chID{"chrome", &createch.Chrome83},
	"custom":         chID{"custom", &createch.Custom},
	"customNoKeys":   chID{"customNoKeys", &createch.CustomNoKeys},
	"customAllKeys":  chID{"customAllKeys", &createch.CustomAllKeys},
	"firefox65":      chID{"firefox65", &createch.Firefox65},
	"grease":         chID{"grease", &createch.Grease},
	"greaseReversed": chID{"greaseReversed", &createch.GreaseReversed},
	"safari14":       chID{"safari14", &createch.Safari14},
}

var jarmMap = map[string]chID{}

func init() {
	for _, j := range createch.JarmAllClientHellos {
		jarmMap[j.Name] = chID{info: j.Name, value: createch.GetJarmClientHello(j)}
	}
}

func printIDs() {
	for id, ch := range customMap {
		fmt.Printf("%s: %s \n", id, ch.info)
	}
	for id, ch := range jarmMap {
		fmt.Printf("%s: %s \n", id, ch.info)
	}
}

func save(filename string, t tls.ClientHelloPreset) error {
	fi2, err := os.Create(filename + ".json")
	if err != nil {
		return err
	}
	defer fi2.Close()

	jsonEncoder := json.NewEncoder(fi2)
	jsonEncoder.SetIndent("", "  ")
	err = jsonEncoder.Encode(t)
	if err != nil {
		return err
	}
	return nil
}

func (command *CreateCHCommand) Run() error {

	if command.ListIDS {
		printIDs()
	} else if command.OutDir != "" {
		err := os.MkdirAll(command.OutDir, 0755)
		if err != nil {
			return err
		}

		if command.CreateCHType == "random" {
			if command.TmpDir == "" {
				log.Fatal().Msg("Please set tmp dir")
			}

			hellos := createch.GetRandomClientHellos(command.RandomCHs, 5081996, command.TmpDir)
			for i := range hellos {
				err := save(filepath.Join(command.OutDir, "random"+strconv.Itoa(i)), hellos[i])
				if err != nil {
					log.Err(err).Str("CH", "random"+strconv.Itoa(i)).Msg("Error saving client hello")
					return err
				}
			}
			return nil
		}

		var saveCHs map[string]chID
		switch command.CreateCHType {
		case "custom":
			saveCHs = customMap
		case "jarm":
			saveCHs = jarmMap
		default:
			log.Error().Str("client-hellos", command.CreateCHType).Msg("Please specify the Client Hellos")
			return ErrPrintHelp
		}
		for k, v := range saveCHs {
			err := save(path.Join(command.OutDir, k), *v.value)
			if err != nil {
				log.Err(err).Str("CH", k).Msg("Error saving client hello")
				return err
			}
		}

	} else {
		log.Error().Msg("Please provide arguments")
		return ErrPrintHelp
	}
	return nil
}
