package createch

import "github.com/tumi8/goscanner/tls"

var greaseValue uint16 = 0x0a0a

var Grease = tls.ClientHelloPreset{
	Ciphers: []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		greaseValue,
	},
	CompressionMethods: []byte{compressionNone},
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
		tls.SignatureScheme(greaseValue),
	},
	StatusRequest:  true,
	Sct:            true,
	SessionTicket:  true,
	Alpn:           []string{"h2", "http/1.1"},
	EcPointFormats: []uint8{0},
	PskKeyExchangeModes: []uint8{
		1, //pskModeDHE
	},
	SupportedVersions: []uint16{
		tls.VersionTLS13,
		tls.VersionTLS12,
		tls.VersionTLS11,
		tls.VersionTLS10,
		greaseValue,
	},
	SupportedGroups: []tls.CurveID{
		tls.CurveID(greaseValue),
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	},
	Version:                tls.VersionTLS12,
	GreaseExtension:        greaseValue,
	ReversedExtensionOrder: false,
	KeyShares:              2,
}
