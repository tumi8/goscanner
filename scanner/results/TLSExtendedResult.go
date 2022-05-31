package results

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/tls"
	"golang.org/x/crypto/cryptobyte"
	"sort"
	"strconv"
	"strings"
	"time"
)

// These are all the extensions where Cisco Mercury or JA3 use the extension data for fingerprinting
// As well as other we evaluated as interesting (everything that is not session specific like Random)
var extensionsWithStaticData = []uint16{
	tls.ExtensionSupportedCurves,         // 10 supported groups
	tls.ExtensionSupportedPoints,         // 11 ec point formats TLS 1.2
	tls.ExtensionSignatureAlgorithms,     // 13
	tls.ExtensionALPN,                    // 16
	tls.ExtensionSupportedVersions,       // 43
	tls.ExtensionPSKModes,                // psk_key_exchange_modes, Should be a client only extension
	tls.ExtensionSignatureAlgorithms,     // 13
	tls.ExtensionSignatureAlgorithmsCert, // 50
	tls.ExtensionCertificateAuthorities,  // 47
	1,                                    // MaxFragmentLength
	28,                                   // RecordSizeLimit
	19,                                   // ClientCertificateType
	20,                                   // ServerCertificateType
	7,                                    // Client Authentication
	8,                                    // Server Authentication
	9,                                    // Cert Type
	15,                                   // Heartbeat
	24,                                   // Token Binding
	27,                                   // Compress Certificate
}

// These extensions are not specific to the application, but specific to the server
var _ = []uint16{
	tls.ExtensionServerName,    // 0
	tls.ExtensionStatusRequest, // 5
	tls.ExtensionSCT,           // 18
	17,                         // Status Request V2
}

func init() {
	sort.Slice(extensionsWithStaticData, func(i, j int) bool { return extensionsWithStaticData[i] < extensionsWithStaticData[j] })
}

type TLSFingerprintResult struct {
	TLSState tls.ConnectionState
}

func (t *TLSFingerprintResult) GetCsvFileName() string {
	return FileTLSVerbose
}

func (t *TLSFingerprintResult) GetCsvHeader() []string {
	return []string{"id", "server_hello_protocol", "server_hello_cipher", "handshake_key_share_group_13", "server_hello_extensions", "encrypted_extensions", "cert_request_extensions", "hello_retry_extensions", "certificate_extensions", "fingerprint"}
}

func (t *TLSFingerprintResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	// Check protocol and cipher
	var protocol, cipher, keyShareGroup string
	if t.TLSState.ServerHello != nil {
		protocol = strconv.Itoa(int(t.TLSState.ServerHello.Vers))
		cipher = strconv.FormatUint(uint64(t.TLSState.ServerHello.CipherSuite), 16)

		if t.TLSState.ServerHello.ServerShare.Group > 0 {
			keyShareGroup = strconv.FormatUint(uint64(t.TLSState.ServerHello.ServerShare.Group), 10)
		} else if t.TLSState.ServerHello.SelectedGroup > 0 {
			keyShareGroup = strconv.FormatUint(uint64(t.TLSState.ServerHello.SelectedGroup), 10)
		}
	}

	tlsFingerprint := fingerprint(protocol, cipher, t.TLSState.SendAlerts, t.TLSState.RecvAlerts, t.TLSState.ServerExtensions, t.TLSState.ServerEncryptedExtensions, t.TLSState.ServerCertRequestExtensions, t.TLSState.HelloRetryRequestExtensions, t.TLSState.CertificateExtensions)

	// Write row in host CSV file
	return writer.Write([]string{
		parentResult.Id.ToString(),
		protocol,
		cipher,
		keyShareGroup,
		stringifyExtensions(t.TLSState.ServerExtensions),
		stringifyExtensions(t.TLSState.ServerEncryptedExtensions),
		stringifyExtensions(t.TLSState.ServerCertRequestExtensions),
		stringifyExtensions(t.TLSState.HelloRetryRequestExtensions),
		stringifyExtensions(t.TLSState.CertificateExtensions),
		tlsFingerprint,
	})
}

func isStatic(extension tls.Extension) bool {
	l := len(extensionsWithStaticData)
	e := extension.Extension
	j := sort.Search(l, func(i int) bool { return (extensionsWithStaticData)[i] >= e })
	return j < l && extensionsWithStaticData[j] == e
}

func stringifyExtensions(extensions []tls.Extension) string {
	if extensions == nil {
		return ""
	}
	jsonData, err := json.Marshal(parseExtensions(extensions))
	if err != nil {
		log.Err(err).Msg("Could not construct json extensions")
	}
	return string(jsonData)
}

func fingerprint(protocol, cipher string, sendAlerts []tls.Alert, recvAlerts []tls.Alert, extensions ...[]tls.Extension) (result string) {
	r := make([]string, len(extensions)+2)
	r[0] = protocol
	r[1] = cipher
	for i := range extensions {
		parsed := parseExtensions(extensions[i])
		for j, e := range extensions[i] {
			if e.Extension == tls.ExtensionKeyShare {
				parsed[j][1] = strconv.FormatUint(uint64(extractKeyShare(e.Data)), 10)
			} else if !isStatic(e) {
				parsed[j][1] = ""
			}
		}
		s := make([]string, len(parsed))
		for j := range parsed {
			s[j] = strings.Join([]string{strconv.Itoa(parsed[j][0].(int)), parsed[j][1].(string)}, ".")
		}
		prepend := ""
		if extensions[i] != nil && len(s) == 0 {
			prepend = "-"
		}
		r[i+2] = prepend + strings.Join(s, "-")
	}

	result = strings.Join(r, "_")
	if len(recvAlerts) > 0 {
		result += "<" + strings.Join(misc.ParseAlerts(recvAlerts), "-")
	}

	if result == "______" {
		result = ""
	}
	//if len(sendAlerts) > 0 {
	//	result += ">" + strings.Join(misc.ParseAlerts(sendAlerts),"-")
	//}
	return
}

func extractKeyShare(extData cryptobyte.String) uint16 {
	var re uint16
	if !extData.ReadUint16(&re) {
		return 0
	}
	return re
}

// Always append extension values if the filter is empty
func parseExtensions(extensions []tls.Extension) [][]interface{} {
	result := make([][]interface{}, len(extensions))
	for i := range extensions {
		result[i] = []interface{}{
			int(extensions[i].Extension),
			base64.RawStdEncoding.EncodeToString(extensions[i].Data),
		}
	}
	return result
}
