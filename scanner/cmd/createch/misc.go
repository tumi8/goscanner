package createch

import (
	"encoding/csv"
	"errors"
	"github.com/rs/zerolog/log"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path"
	"reflect"
)

func GetRandomSubsetPermutation(input interface{}, min int) interface{} {
	s := reflect.ValueOf(input)
	if s.Kind() != reflect.Slice {
		panic("InterfaceSlice() given a non-slice type")
	}

	// Keep the distinction between nil and empty slice input
	if s.IsNil() {
		return nil
	}

	inputType := s.Index(0).Type()

	ret := reflect.MakeSlice(reflect.SliceOf(inputType), s.Len(), s.Len())

	for i := 0; i < s.Len(); i++ {
		ret.Index(i).Set(s.Index(i))
	}

	rand.Shuffle(ret.Len(), func(i, j int) {
		tmp := ret.Index(i).Interface()
		ret.Index(i).Set(ret.Index(j))
		ret.Index(j).Set(reflect.ValueOf(tmp))
	})
	size := rand.Intn(ret.Len()+1-min) + min
	return ret.Slice(0, size).Interface()
}

func readAssetCsv(asset string, transform func([]string) string) (result []string) {
	assetFile, err := os.Open(asset)
	if err != nil {
		log.Fatal().Err(err).Msg("Could not load asset")
	}

	csvReader := csv.NewReader(assetFile)
	_, _ = csvReader.Read() // Header
	for line, err := csvReader.Read(); err == nil; line, err = csvReader.Read() {
		record := transform(line)
		if record != "" {
			result = append(result, record)
		}
	}
	return
}

func LocalDownload(filepath string, url string) {
	if _, err := os.Stat(filepath); errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(path.Dir(filepath), 0755)
		if err != nil {
			log.Fatal().Err(err).Msg("Error saving file")
		}

		resp, err := http.Get(url)
		if err != nil {
			log.Fatal().Err(err).Msg("Error saving file")
		}
		defer resp.Body.Close()

		out, err := os.Create(filepath)
		if err != nil {
			log.Fatal().Err(err).Msg("Error saving file")
		}
		defer out.Close()

		_, err = io.Copy(out, resp.Body)
		if err != nil {
			log.Fatal().Err(err).Msg("Error saving file")
		}
	}
}
