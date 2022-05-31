package createch

import "github.com/tumi8/goscanner/tls"

var Chrome70 = tls.ClientHelloPreset{
	Version: tls.VersionTLS12,
	Ciphers: []uint16{
		greaseValue,
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
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
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
		tls.PKCS1WithSHA1,
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
		// 0x6a6a seems to be custom chrome version
		tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10,
	},
	SupportedGroups: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521},
	// extended_master_secret: true,
	// compress_certificate: 2
	KeyShares: 1,
}

var Chrome83 = tls.ClientHelloPreset{
	Ciphers: []uint16{
		// GREASE_PLACEHOLDER,
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
		//GREASE_PLACEHOLDER,
		tls.VersionTLS13,
		tls.VersionTLS12,
		tls.VersionTLS11,
		tls.VersionTLS10,
	},
	SupportedGroups: []tls.CurveID{
		//tls.CurveID(GREASE_PLACEHOLDER),
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	},
	Version:   tls.VersionTLS12,
	KeyShares: 1,
}
