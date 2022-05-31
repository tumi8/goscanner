package createch

import (
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/tls"
	"math/rand"
	"path"
	"reflect"
	"strconv"
	"strings"
)

var allCiphers []uint16
var allGroups []tls.CurveID
var allAlpns []string
var allSignatures []tls.SignatureScheme

var allUnderstandableValues = tls.ClientHelloPreset{
	Ciphers: []uint16{
		// TLS 1.3 cipher suites.
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,

		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_RC4_128_SHA,

		greaseValue,
	},
	CompressionMethods: []uint8{0}, // Only NULL compression allowed

	SignatureAlgorithms: []tls.SignatureScheme{
		// EdDSA algorithms.
		tls.Ed25519,

		// ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
		tls.ECDSAWithP256AndSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.ECDSAWithP521AndSHA512,
		// RSASSA-PSS algorithms with public key OID rsaEncryption.
		tls.PSSWithSHA256,
		tls.PSSWithSHA384,
		tls.PSSWithSHA512,

		tls.PKCS1WithSHA256,
		tls.PKCS1WithSHA384,
		tls.PKCS1WithSHA512,

		// Legacy signature and hash algorithms for TLS 1.2.
		tls.ECDSAWithSHA1,
		tls.PKCS1WithSHA1,
	},
	Alpn:                []string{"h2", "http/1.1", "http/1.0"},
	EcPointFormats:      []uint8{0},
	PskKeyExchangeModes: []uint8{1, 0},
	SupportedVersions:   []uint16{tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10},
	SupportedGroups: []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	},
}

var loadedValues bool

func loadAllValues(tmpDir string) {
	ciphers := path.Join(tmpDir, "iana_ciphers.csv")
	alpn := path.Join(tmpDir, "iana_alpn.csv")
	signatures := path.Join(tmpDir, "iana_signature_schemes.csv")
	groups := path.Join(tmpDir, "iana_groups.csv")
	LocalDownload(ciphers, "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv")
	LocalDownload(signatures, "https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv")
	LocalDownload(alpn, "https://www.iana.org/assignments/tls-extensiontype-values/alpn-protocol-ids.csv")
	LocalDownload(groups, "https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv")

	parseCiphers := func(line []string) (r string) {
		if strings.HasPrefix(line[1], "TLS_") && line[1] != "TLS_FALLBACK_SCSV" {
			t := strings.Split(line[0], ",")
			r = t[0] + strings.ReplaceAll(t[1], "0x", "")
		}
		return
	}
	for _, c := range readAssetCsv(ciphers, parseCiphers) {
		i, err := strconv.ParseUint(c, 0, 16)
		if err != nil {
			log.Fatal().Err(err).Msg("Could not parse number")
		}
		allCiphers = append(allCiphers, uint16(i))
	}
	parseAlpn := func(line []string) (r string) {
		if strings.Contains(line[1], "(") && strings.Contains(line[1], ")") {
			protocol := line[1][strings.Index(line[1], "(")+1 : strings.Index(line[1], ")")]
			r = strings.Trim(protocol, "\"“”")
		}
		return
	}
	allAlpns = readAssetCsv(alpn, parseAlpn)

	// sort.Slice(allAlpns, func(i, j int) bool { return allAlpns[i] < allAlpns[j] })
	parseGroups := func(line []string) (r string) {
		if strings.ContainsAny(line[3], "YN") {
			r = line[0]
		}
		return
	}

	for _, g := range readAssetCsv(groups, parseGroups) {
		i, err := strconv.Atoi(g)
		if err != nil {
			log.Fatal().Err(err).Msg("Could not parse group")
		}
		allGroups = append(allGroups, tls.CurveID(uint16(i)))
	}

	parseSignatureSchemes := func(line []string) (r string) {
		if strings.ContainsAny(line[2], "YN") {
			r = line[0]
		}
		return
	}
	for _, s := range readAssetCsv(signatures, parseSignatureSchemes) {
		i, err := strconv.ParseUint(s, 0, 16)
		if err != nil {
			log.Fatal().Err(err).Msg("Could not parse signature scheme")
		}
		allSignatures = append(allSignatures, tls.SignatureScheme(i))
	}
}

func randBool() bool {
	return rand.Intn(2) == 0
}

func GetRandomClientHello(allValues bool) tls.ClientHelloPreset {
	result := tls.ClientHelloPreset{}

	ciphers := allUnderstandableValues.Ciphers
	groups := allUnderstandableValues.SupportedGroups
	alpns := allUnderstandableValues.Alpn
	signatures := allUnderstandableValues.SignatureAlgorithms
	if allValues {
		// Use values the goscanner cannot even understand
		ciphers = allCiphers
		groups = allGroups
		alpns = allAlpns
		signatures = allSignatures
	}

	result.Ciphers = GetRandomSubsetPermutation(ciphers, 3).([]uint16)

	result.CompressionMethods = GetRandomSubsetPermutation(allUnderstandableValues.CompressionMethods, 0).([]uint8)
	result.RenegotiationInfo = randBool()

	renegotiationOptions := []tls.RenegotiationSupport{tls.RenegotiateNever, tls.RenegotiateOnceAsClient, tls.RenegotiateFreelyAsClient}
	result.Renegotiation = renegotiationOptions[rand.Intn(len(renegotiationOptions))]

	result.SignatureAlgorithms = GetRandomSubsetPermutation(signatures, 0).([]tls.SignatureScheme)

	result.StatusRequest = randBool()
	result.Sct = randBool()
	result.SessionTicket = randBool()

	result.Alpn = GetRandomSubsetPermutation(alpns, 0).([]string)

	result.EcPointFormats = GetRandomSubsetPermutation(allUnderstandableValues.EcPointFormats, 0).([]uint8)
	result.PskKeyExchangeModes = GetRandomSubsetPermutation(allUnderstandableValues.PskKeyExchangeModes, 0).([]uint8)
	result.SupportedVersions = GetRandomSubsetPermutation(allUnderstandableValues.SupportedVersions, 0).([]uint16)

	hasTLS13 := false
	for _, v := range result.SupportedVersions {
		if v == tls.VersionTLS13 {
			hasTLS13 = true
		}
	}

	result.SupportedGroups = GetRandomSubsetPermutation(groups, 1).([]tls.CurveID)

	result.Version = allUnderstandableValues.SupportedVersions[rand.Intn(4)]

	maxKeyShares := 0
	firstIs521 := false
	for _, g := range result.SupportedGroups {
		for _, g2 := range allUnderstandableValues.SupportedGroups {
			if g == g2 {
				if maxKeyShares == 0 && g == tls.CurveP521 {
					firstIs521 = true
				}
				maxKeyShares += 1
			}
		}
	}
	if maxKeyShares > 0 && !firstIs521 {
		// 25 % chance to send no KeyShare. And Never for CurveP521, too expensive
		result.KeyShares = 1
		if randBool() && randBool() {
			result.KeyShares = 0
		}
	}

	if randBool() {
		result.SupportedGroups = GetRandomSubsetPermutation(append(result.SupportedGroups, tls.CurveID(greaseValue)), len(result.SupportedGroups)+1).([]tls.CurveID)
	}

	if randBool() {
		result.GreaseExtension = tls.GreaseValues[rand.Intn(len(tls.GreaseValues))]
	}

	result.ReversedExtensionOrder = randBool()

	if randBool() {
		// Min: 64 Max: TLS 1.2 2^14
		// If rsl is 5 we skip this extension
		rsl := rand.Intn(14-5+1) + 5 // [5,14]
		if rsl != 5 {
			result.RecordSizeLimit = uint16(1 << rsl) // 2^rsl = 1<<rsl
		}
		if rsl == 14 && hasTLS13 && randBool() {
			// Max TLS1.3 2^14+1
			result.RecordSizeLimit++
		}
	} else {
		maxFragmentLength := rand.Intn(5)
		if maxFragmentLength > 0 {
			result.MaxFragmentLength = uint8(maxFragmentLength)
		}
	}

	return result
}

func GetRandomClientHellos(n int, seed int64, tmpDir string) []tls.ClientHelloPreset {
	if !loadedValues {
		loadAllValues(tmpDir)
		loadedValues = true
	}

	result := make([]tls.ClientHelloPreset, n)
	i := 0
	allValues := false
	for i < n {
		rand.Seed(seed + int64(i))
		allValues = !allValues
		result[i] = GetRandomClientHello(allValues)
		ok := true
		for j := 0; j < i; j++ {
			if reflect.DeepEqual(result[j], result[i]) {
				ok = false
			}
		}
		if ok {
			i++
		}
	}
	return result
}
