package createch

import "github.com/tumi8/goscanner/tls"

var greaseValue4 = uint16(0x4a4a)
var greaseValueF = uint16(0xfafa)

var Safari14 = tls.ClientHelloPreset{
	Version: tls.VersionTLS12,
	Ciphers: []uint16{
		greaseValue4,
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		uint16(0xc02c),
		uint16(0xc02b),
		uint16(0xcca9),
		uint16(0xc030),
		uint16(0xc02f),
		uint16(0xcca8),
		uint16(0xc024),
		uint16(0xc023),
		uint16(0xc00a),
		uint16(0xc009),
		uint16(0xc028),
		uint16(0xc027),
		uint16(0xc014),
		uint16(0xc013),
		uint16(0x009d),
		uint16(0x009c),
		uint16(0x003d),
		uint16(0x003c),
		uint16(0x0035),
		uint16(0x002f),
		uint16(0xc008),
		uint16(0xc012),
		uint16(0x000a),
	},
	CompressionMethods: []byte{compressionNone},
	GreaseExtension:    greaseValueF,
	RenegotiationInfo:  true,
	SupportedGroups: []tls.CurveID{
		tls.CurveID(greaseValueF),
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	},
	Renegotiation: tls.RenegotiateOnceAsClient,

	SignatureAlgorithms: []tls.SignatureScheme{
		tls.ECDSAWithP256AndSHA256,
		tls.PSSWithSHA256,
		tls.SignatureScheme(0x0401), // rsa_pkcs1_sha256
		tls.ECDSAWithP384AndSHA384,
		tls.SignatureScheme(0x0203), // ecdsa_sha1
		tls.PSSWithSHA384,           // Its doubled in safari
		tls.PSSWithSHA384,
		tls.PKCS1WithSHA384,
		tls.PSSWithSHA512,
		tls.PKCS1WithSHA512,
		tls.PKCS1WithSHA1,
	},
	EcPointFormats: []uint8{0},
	Alpn:           []string{"h2", "http/1.1"},
	StatusRequest:  true,
	SessionTicket:  true,
	Sct:            true,
	PskKeyExchangeModes: []uint8{
		1, //pskModeDHE
	},
	SupportedVersions: []uint16{
		greaseValueF, tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10,
	},
	KeyShares: 1,
}
