package results

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/tls"
	"strconv"
	"strings"
	"time"
)

var deepTLSHeader = []string{"id", "status", "num_chs", "timeouts", "fingerprint", "scan_finished_early", "ssl_version_30", "tls_version_10", "tls_version_11", "tls_version_12", "tls_version_13", "ciphers", "prefer_client_ciphers", "ciphers_complete", "supported_groups", "prefer_client_groups", "prefer_client_groups_with_key_share", "groups_complete", "alpn", "prefer_client_alpn",
	"extended_master_secret", "status_request", "encrypt_then_mac", "max_fragment_length", "record_size_limit", "inappropriate_fallback_support", "supported_points", "signature_algorithms", "signature_algorithms_cert", "certificate_authorities", "heartbeats", "alerts",
	"extensions_sh", "extensions_ee", "extensions_cr", "extensions_hrr", "extensions_ct", "extensions_consistent", "version_error_behavior", "cipher_error_behavior", "supported_groups_error_behavior", "alpn_error_behavior", "cipher_ignore_sent_values", "supported_groups_ignore_sent_values", "alpn_ignore_sent_values"}

type ServerModel struct {
	VersionSSLv3 *string
	VersionTLS10 *string
	VersionTLS11 *string
	VersionTLS12 *string
	VersionTLS13 *string
	VersionError *string

	CipherPrio         []uint16
	CipherError        *string
	CipherDone         *bool
	PreferClientCipher *bool
	IgnoresCipher      *bool

	SupportedGroupsPrio            []tls.CurveID
	GroupsError                    *string
	SupportedGroupsDone            *bool
	PreferClientGroups             *bool
	PreferClientGroupsWithKeyShare *bool
	IgnoresGroups                  *bool

	AlpnPrio         []string
	AlpnError        *string
	IgnoresAlpn      *bool
	PreferClientAlpn *bool

	ExtendedMasterSecret             *bool
	StatusRequest                    *bool
	EncryptThenMac                   *bool
	MaxFragmentSizeSupport           *bool
	RecordSizeLimitSupport           *bool
	InappropriateFallbackSupport     *bool
	SupportedPoints                  []string
	SupportedSignaturealgorithms     []uint16
	SupportedSignaturealgorithmsCert []uint16
	CertificateAuthorities           []string

	Heartbeat []uint8

	AlertSequence []tls.Alert

	ExtensionOrderSH  [][]uint16
	ExtensionOrderEE  [][]uint16
	ExtensionOrderCR  [][]uint16
	ExtensionOrderHRR [][]uint16
	ExtensionOrderCT  [][]uint16

	ExtensionsConsistent bool

	CipherScanComplete bool
	ScanKnownCipher    bool
	ReEnableCipherScan bool
}

type DissecTLSResult struct {
	Model          ServerModel
	NumRequests    int
	NumTimeouts    int
	InformationCut bool
	Timeout        bool
	TcpError       bool
}

func (t DissecTLSResult) GetCsvFileName() string {
	return FileDissecTLS
}

func (t DissecTLSResult) GetCsvHeader() []string {
	return deepTLSHeader
}

func (t DissecTLSResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	var cipherPrio []string
	for _, c := range t.Model.CipherPrio {
		cipherPrio = append(cipherPrio, strconv.FormatUint(uint64(c), 16))
	}
	var groups []string
	for _, c := range t.Model.SupportedGroupsPrio {
		groups = append(groups, strconv.FormatUint(uint64(c), 10))
	}
	var beats []string
	for _, c := range t.Model.Heartbeat {
		beats = append(beats, strconv.FormatUint(uint64(c), 10))
	}
	var alerts []string
	for _, c := range t.Model.AlertSequence {
		alerts = append(alerts, strconv.FormatUint(uint64(c), 10))
	}
	var sigAlgs []string
	for _, c := range t.Model.SupportedSignaturealgorithms {
		sigAlgs = append(sigAlgs, strconv.FormatUint(uint64(c), 10))
	}
	var sigAlgCerts []string
	for _, c := range t.Model.SupportedSignaturealgorithmsCert {
		sigAlgCerts = append(sigAlgCerts, strconv.FormatUint(uint64(c), 10))
	}
	status := "SUCCESS"
	if t.Timeout {
		status = "TIMEOUT"
	} else if t.Model.VersionTLS10 == nil || t.Model.VersionTLS11 == nil || t.Model.VersionTLS12 == nil || t.Model.VersionTLS13 == nil {
		status = "INCOMPLETE"
	} else if !(strToString(t.Model.VersionTLS10) == "True" || strToString(t.Model.VersionTLS11) == "True" || strToString(t.Model.VersionTLS12) == "True" || strToString(t.Model.VersionTLS13) == "True") {
		status = "NO_TLS"
	} else if t.TcpError {
		status = "TCP ERROR"
	}

	result := []string{
		boolToString(&t.InformationCut),

		strToString(t.Model.VersionSSLv3),
		strToString(t.Model.VersionTLS10),
		strToString(t.Model.VersionTLS11),
		strToString(t.Model.VersionTLS12),
		strToString(t.Model.VersionTLS13),

		strings.Join(cipherPrio, "-"),
		boolToString(t.Model.PreferClientCipher),
		boolToString(t.Model.CipherDone),
		strings.Join(groups, "-"),
		boolToString(t.Model.PreferClientGroups),
		boolToString(t.Model.PreferClientGroupsWithKeyShare),
		boolToString(t.Model.SupportedGroupsDone),
		strings.Join(t.Model.AlpnPrio, "-"),
		boolToString(t.Model.PreferClientAlpn),

		boolToString(t.Model.ExtendedMasterSecret),
		boolToString(t.Model.StatusRequest),
		boolToString(t.Model.EncryptThenMac),
		boolToString(t.Model.MaxFragmentSizeSupport),
		boolToString(t.Model.RecordSizeLimitSupport),

		boolToString(t.Model.InappropriateFallbackSupport),

		strings.Join(t.Model.SupportedPoints, ","),
		strings.Join(sigAlgs, "-"),
		strings.Join(sigAlgCerts, "-"),
		strings.Join(t.Model.CertificateAuthorities, "-"),

		strings.Join(beats, "-"),

		strings.Join(alerts, "-"),

		parseExtensionOrder(t.Model.ExtensionOrderSH),
		parseExtensionOrder(t.Model.ExtensionOrderEE),
		parseExtensionOrder(t.Model.ExtensionOrderCR),
		parseExtensionOrder(t.Model.ExtensionOrderHRR),
		parseExtensionOrder(t.Model.ExtensionOrderCT),
		boolToString(&t.Model.ExtensionsConsistent),

		strToString(t.Model.VersionError),
		strToString(t.Model.CipherError),
		strToString(t.Model.GroupsError),
		strToString(t.Model.AlpnError),
		boolToString(t.Model.IgnoresCipher),
		boolToString(t.Model.IgnoresGroups),
		boolToString(t.Model.IgnoresAlpn),
	}

	hash := sha256.Sum256([]byte(strings.Join(result, "|")))

	return writer.Write(append([]string{
		parentResult.Id.ToString(),
		status,
		strconv.Itoa(t.NumRequests),
		strconv.Itoa(t.NumTimeouts),
		hex.EncodeToString(hash[:]),
	}, result...))
}

func parseExtensionOrder(order [][]uint16) string {
	if order == nil || len(order) == 0 {
		return ""
	}
	jsonData, err := json.Marshal(order)
	if err != nil {
		log.Err(err).Msg("Could not construct json extensions")
	}
	return string(jsonData)
}

func strToString(in *string) string {
	if in == nil {
		return ""
	}
	return *in
}

func boolToString(in *bool) string {
	if in == nil {
		return ""
	} else if *in {
		return "1"
	}
	return "0"
}
