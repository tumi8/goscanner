package createch

import "github.com/tumi8/goscanner/tls"

var Firefox65 = tls.ClientHelloPreset{
	Version: tls.VersionTLS12,
	Ciphers: []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		uint16(0x0033), // tls.FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
		uint16(0x0039), // tls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	},
	CompressionMethods: []byte{compressionNone},
	RenegotiationInfo:  true,
	Renegotiation:      tls.RenegotiateOnceAsClient,
	SignatureAlgorithms: []tls.SignatureScheme{
		tls.ECDSAWithP256AndSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.ECDSAWithP521AndSHA512,
		tls.PSSWithSHA256,
		tls.PSSWithSHA384,
		tls.PSSWithSHA512,
		tls.PKCS1WithSHA256,
		tls.PKCS1WithSHA384,
		tls.PKCS1WithSHA512,
		tls.ECDSAWithSHA1,
		tls.PKCS1WithSHA1,
	},
	StatusRequest:  true,
	Sct:            true,
	SessionTicket:  true,
	Alpn:           []string{"h2", "http/1.1"},
	EcPointFormats: []uint8{},
	PskKeyExchangeModes: []uint8{
		1, //pskModeDHE
	},
	SupportedVersions: []uint16{
		tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10,
	},
	SupportedGroups: []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
		tls.CurveID(uint16(0x0100)), //FakeFFDHE2048
		tls.CurveID(uint16(0x0101)), //FakeFFDHE3072
	},
	RecordSizeLimit: 0x4001,
	KeyShares:       1,
}
