package createch

import (
	"github.com/tumi8/goscanner/tls"
	"strconv"
)

/*
These CHs are inspired and as close as possible to the ones sent by JARM (https://github.com/salesforce/jarm)
*/

type ClientHelloParameterOrder uint

var FORWARD ClientHelloParameterOrder = 0
var REVERSE ClientHelloParameterOrder = 1
var TOP_HALF ClientHelloParameterOrder = 2
var BOTTOM_HALF ClientHelloParameterOrder = 3
var MIDDLE_OUT ClientHelloParameterOrder = 4

type JarmSettings struct {
	Name                 string
	Version              uint16
	Ciphers              string
	CipherOrder          ClientHelloParameterOrder
	Grease               uint16
	RareALPN             bool
	VersionSupport       string
	ExtensionValueOrder  ClientHelloParameterOrder
	ExtendedMasterSecret bool
}

var JarmAllClientHellos = []JarmSettings{
	{
		Name:                "tls1_2_forward",
		Version:             tls.VersionTLS12,
		Ciphers:             "ALL",
		CipherOrder:         FORWARD,
		Grease:              0x0a0a,
		RareALPN:            false,
		VersionSupport:      "1.2_SUPPORT",
		ExtensionValueOrder: REVERSE,
	}, {
		Name:                "tls1_2_reverse",
		Version:             tls.VersionTLS12,
		Ciphers:             "ALL",
		CipherOrder:         REVERSE,
		Grease:              0x0a0a,
		RareALPN:            false,
		VersionSupport:      "1.2_SUPPORT",
		ExtensionValueOrder: FORWARD,
	}, {
		Name:                "tls1_2_top_half",
		Version:             tls.VersionTLS12,
		Ciphers:             "ALL",
		CipherOrder:         TOP_HALF,
		Grease:              0x0a0a,
		RareALPN:            false,
		VersionSupport:      "NO_SUPPORT",
		ExtensionValueOrder: FORWARD,
	}, {
		Name:                 "tls1_2_bottom_half",
		Version:              tls.VersionTLS12,
		Ciphers:              "ALL",
		CipherOrder:          BOTTOM_HALF,
		Grease:               0x0a0a,
		RareALPN:             true,
		VersionSupport:       "NO_SUPPORT",
		ExtensionValueOrder:  FORWARD,
		ExtendedMasterSecret: true,
	}, {
		Name:                "tls1_2_middle_out",
		Version:             tls.VersionTLS12,
		Ciphers:             "ALL",
		CipherOrder:         MIDDLE_OUT,
		Grease:              0x0a0a,
		RareALPN:            true,
		VersionSupport:      "NO_SUPPORT",
		ExtensionValueOrder: REVERSE,
	}, {
		Name:                "tls1_1_forward",
		Version:             tls.VersionTLS11,
		Ciphers:             "ALL",
		CipherOrder:         FORWARD,
		Grease:              0x0a0a,
		RareALPN:            false,
		VersionSupport:      "NO_SUPPORT",
		ExtensionValueOrder: FORWARD,
	}, {
		Name:                "tls1_3_forward",
		Version:             tls.VersionTLS13,
		Ciphers:             "ALL",
		CipherOrder:         FORWARD,
		Grease:              0x0a0a,
		RareALPN:            false,
		VersionSupport:      "1.3_SUPPORT",
		ExtensionValueOrder: REVERSE,
	}, {
		Name:                "tls1_3_reverse",
		Version:             tls.VersionTLS13,
		Ciphers:             "ALL",
		CipherOrder:         REVERSE,
		Grease:              0x0a0a,
		RareALPN:            false,
		VersionSupport:      "1.3_SUPPORT",
		ExtensionValueOrder: FORWARD,
	}, {
		Name:                "tls1_3_invalid",
		Version:             tls.VersionTLS13,
		Ciphers:             "NO1.3",
		CipherOrder:         FORWARD,
		Grease:              0x0a0a,
		RareALPN:            false,
		VersionSupport:      "1.3_SUPPORT",
		ExtensionValueOrder: FORWARD,
	}, {
		Name:                "tls1_3_middle_out",
		Version:             tls.VersionTLS13,
		Ciphers:             "ALL",
		CipherOrder:         MIDDLE_OUT,
		Grease:              0x0a0a,
		RareALPN:            false,
		VersionSupport:      "1.3_SUPPORT",
		ExtensionValueOrder: REVERSE,
	},
}

func changeOrder(input []uint16, order ClientHelloParameterOrder) (output []uint16) {
	inputLength := len(input)
	if order == REVERSE {
		output = make([]uint16, inputLength)
		j := inputLength - 1
		for i := range input {
			output[j] = input[i]
			j--
		}
	} else if order == BOTTOM_HALF {
		if inputLength%2 == 1 {
			output = input[(inputLength/2)+1:]
		}
		output = input[inputLength/2:]
	} else if order == TOP_HALF {
		output = changeOrder(changeOrder(input, REVERSE), BOTTOM_HALF)
		if inputLength%2 == 1 {
			output = append([]uint16{input[inputLength/2]}, output...)
		}
	} else if order == MIDDLE_OUT {
		middle := inputLength / 2
		if inputLength%2 == 1 {
			output = append(output, input[middle])
			for i := 1; i <= middle; i++ {
				output = append(output, input[middle+i])
				output = append(output, input[middle-i])
			}
		} else {
			for i := 1; i <= middle; i++ {
				output = append(output, input[middle-1+i])
				output = append(output, input[middle-i])
			}
		}
	} else {
		panic("Unknown order: " + strconv.Itoa(int(order)))
	}
	return
}

func changeOrderString(input []string, order ClientHelloParameterOrder) (output []string) {
	inputLength := len(input)
	if order == REVERSE {
		output = make([]string, inputLength)
		j := inputLength - 1
		for i := range input {
			output[j] = input[i]
			j--
		}
	} else {
		panic("Unknown order: " + strconv.Itoa(int(order)))
	}
	return
}

var supported_version_12 = []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12}
var supported_version_13 = append(supported_version_12, tls.VersionTLS13)

func GetJarmClientHello(config JarmSettings) *tls.ClientHelloPreset {
	versions := getSupportedVersion(config)
	alpn := getALpn(config)
	groups := []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	if config.Grease > 0 {
		groups = append([]tls.CurveID{tls.CurveID(config.Grease)}, groups...)
	}
	return &tls.ClientHelloPreset{
		Ciphers:            getCiphers(config),
		CompressionMethods: []uint8{0},
		RenegotiationInfo:  true,
		Renegotiation:      tls.RenegotiateOnceAsClient,
		SignatureAlgorithms: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.PSSWithSHA256,
			tls.PKCS1WithSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.PSSWithSHA384,
			tls.PKCS1WithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA512,
			tls.PKCS1WithSHA1,
		},
		StatusRequest:  false,
		Sct:            false,
		SessionTicket:  true,
		Alpn:           alpn,
		EcPointFormats: []uint8{0},
		PskKeyExchangeModes: []uint8{
			1, //pskModeDHE
		},
		SupportedVersions:    versions,
		SupportedGroups:      groups,
		MaxFragmentLength:    1,
		Version:              config.Version,
		ExtendedMasterSecret: config.ExtendedMasterSecret,
		GreaseExtension:      config.Grease,
	}
}

func getSupportedVersion(config JarmSettings) (versions []uint16) {
	if config.VersionSupport == "1.2_SUPPORT" {
		versions = supported_version_12
	} else if config.VersionSupport == "1.3_SUPPORT" {
		versions = supported_version_13
	} else {
		return
	}
	if config.Grease > 0 {
		versions = append([]uint16{config.Grease}, versions...)
	}
	if config.ExtensionValueOrder != FORWARD {
		versions = changeOrder(versions, config.ExtensionValueOrder)
	}
	return
}

func getALpn(config JarmSettings) (result []string) {
	all := []string{"http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", "h2", "h2c", "hq"}
	uncommon := []string{"http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "hq"}

	if config.RareALPN {
		result = uncommon
	} else {
		result = all
	}
	if config.ExtensionValueOrder != FORWARD {
		result = changeOrderString(result, config.ExtensionValueOrder)
	}
	return
}

func getCiphers(config JarmSettings) (result []uint16) {
	if config.Ciphers == "ALL" {
		result = []uint16{0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a, 0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0x1302, 0x1301, 0xcc14, 0xc007, 0xc012, 0xc013, 0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0x1305, 0x1304, 0x1303, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0, 0x009c, 0x0035, 0x003d, 0xc09d, 0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005}
	} else if config.Ciphers == "NO1.3" {
		result = []uint16{0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a, 0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0xcc14, 0xc007, 0xc012, 0xc013, 0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0, 0x009c, 0x0035, 0x003d, 0xc09d, 0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005}
	} else {
		panic("Unknown Cipher Option " + config.Ciphers)
	}
	if config.CipherOrder != FORWARD {
		result = changeOrder(result, config.CipherOrder)
	}
	if config.Grease > 0 {
		result = append([]uint16{config.Grease}, result...)
	}
	return
}
