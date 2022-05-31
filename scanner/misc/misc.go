package misc

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"github.com/rs/zerolog"
	"github.com/tumi8/goscanner/tls"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"fmt"
	"github.com/bt51/ntpclient"
	"github.com/rs/zerolog/log"
)

var idCounter uint32 = 0
var defaultClientHello string
var clientHellos map[string]*tls.ClientHelloPreset

type SessionUID uint32

func GetSessionUID() SessionUID {
	tmpId := atomic.AddUint32(&idCounter, 1)
	return SessionUID(tmpId)
}

func (s SessionUID) ToString() string {
	return strconv.FormatUint(uint64(s), 10)
}

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

func GetMD5(input []byte) []byte {
	hash := md5.Sum(input)
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
		log.Warn().Err(err).Msg("Get NTP time failed")
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

func ByteToMb(b uint64) string {
	return strconv.FormatUint(b/1024/1024, 10) + "mb"
}

func RunCommandToLog(c *exec.Cmd, event *zerolog.Event) {
	out, err := c.Output()
	cmd := c.Path + " " + strings.Join(c.Args, " ")
	if err == nil {
		event.Str(cmd, strings.TrimSuffix(string(out), "\n"))
	} else {
		event.AnErr(cmd, err)
	}
}

func ToJSONIntArray(input []int) string {
	if input == nil || len(input) == 0 {
		return ""
	}
	jsonData, err := json.Marshal(input)
	if err != nil {
		log.Fatal().Err(err).Msg("Could not construct json array")
	}
	return string(jsonData)
}

func ToJSONArray(input []string) string {
	if input == nil || len(input) == 0 {
		return ""
	}
	var sb strings.Builder
	encoder := json.NewEncoder(&sb)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(input)
	if err != nil {
		log.Fatal().Err(err).Msg("Could not construct json array")
	}
	return strings.TrimSpace(sb.String())
}

func ToCompactBinary(input *bool) string {
	if input == nil {
		return ""
	}
	if *input {
		return "1"
	}
	return "0"
}

func MaxInt64(a, b int64) int64 {
	if a < b {
		return b
	}
	return a
}

func PrintStacktrace(all bool) {
	n := 0
	buf := make([]byte, 1024)
	for {
		n = runtime.Stack(buf, all)
		if n < len(buf) {
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	fmt.Printf("\n%s", buf[:n])
	log.Error().Msgf("\n%s", buf[:n])
}

func DumpMemProfile(outputDir string, name string) {
	memFile := filepath.Join(outputDir, name+".prof")
	f, err := os.Create(memFile)
	if err != nil {
		log.Panic().Str("name", name).Err(err).Msg("Could not write mem profile")
	}
	err = pprof.WriteHeapProfile(f)
	if err != nil {
		log.Panic().Str("name", name).Err(err).Msg("Could dump mem profile")
	}
	err = f.Close()
	if err != nil {
		log.Panic().Str("name", name).Err(err).Msg("Could close mem profile")
	}

}

func LoadCustomCH(filename string) (*tls.ClientHelloPreset, error) {
	var t *tls.ClientHelloPreset
	fi, err := os.Open(filename)
	if err != nil {
		return t, err
	}
	defer fi.Close()

	decoder := json.NewDecoder(fi)
	err = decoder.Decode(&t)
	if err != nil {
		return t, err
	}

	return t, nil
}

func LoadClientHellos(opts *Options) {
	clientHellos = make(map[string]*tls.ClientHelloPreset)
	if opts.CustomClientHello != "" {
		err := addClientHelloToMap(clientHellos, opts.CustomClientHello)
		if err != nil {
			log.Fatal().Err(err).Msg("Could not load custom client hello")
		}
		defaultClientHello = path.Base(opts.CustomClientHello)
	}
	if opts.CustomClientHelloDir != "" {
		err := filepath.Walk(opts.CustomClientHelloDir, func(chPath string, info os.FileInfo, err error) error {
			if err != nil {
				log.Fatal().Str("ClientHello", chPath).Err(err).Msg("Could not read client hello")
				return err
			}
			if !info.IsDir() && strings.HasSuffix(chPath, ".json") {
				err := addClientHelloToMap(clientHellos, chPath)
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			log.Fatal().Str("dir", opts.CustomClientHelloDir).Err(err).Msg("Error loading all client hellos from directory")
		}
		log.Info().Int("Total", len(clientHellos)/2).Msg("Loaded multiple Client Hellos")
	}

}

func addClientHelloToMap(chMap map[string]*tls.ClientHelloPreset, filename string) error {
	ch, err := LoadCustomCH(filename)
	if err != nil {
		return err
	}
	name := path.Base(filename)
	chMap[name] = ch
	chMap[strings.ReplaceAll(name, ".json", "")] = ch
	return nil
}

func GetClientHello(name string) (ch *tls.ClientHelloPreset) {
	if name == "" {
		name = defaultClientHello
	}
	if name != "" {
		var present bool
		ch, present = clientHellos[name]
		if !present {
			log.Error().Str("CH", name).Msg("Could not find specified client hello")
		}
	}
	return
}

func IsClosedConnErr(err error) bool {
	return strings.Contains(err.Error(), "closed")
}

func IsStdInPresent() bool {
	fi, err := os.Stdin.Stat()

	if err != nil {
		log.Fatal().Err(err).Msg("Could not read Stdin stats")
	}
	return fi.Mode()&os.ModeNamedPipe != 0
}

func ParseAlerts(alerts []tls.Alert) []string {
	result := make([]string, len(alerts))
	for i := range alerts {
		result[i] = strconv.Itoa(int(alerts[i].GetCode()))
	}
	return result
}

func NewTrue() *bool {
	i := true
	return &i
}

func NewFalse() *bool {
	i := false
	return &i
}

type LogWriter struct{}

func (LogWriter) Write(p []byte) (n int, err error) {
	log.Debug().Msg(strings.TrimSpace(string(p)))
	return
}
