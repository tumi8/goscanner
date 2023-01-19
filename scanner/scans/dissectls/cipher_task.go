package dissectls

import (
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
	"sort"
	"strings"
)

type CipherTask struct {
	ScanCiphers          []uint16
	isDone               bool
	lastCipher           uint16
	preferClient         *bool
	scanForPreference    bool
	preferenceImpossible bool
	unconfiguredCipher   bool
	scanNo13             bool
	errorBehavior        string
}

var ScannerSupportedCiphers = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
}

func init() {
	ScannerSupportedCiphers = append(ScannerSupportedCiphers, ScannerSupported12Ciphers...)
}

var ScannerSupported12Ciphers = []uint16{
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
}

func (c *CipherTask) SetCHValues(preset *tls.ClientHelloPreset, model *results.ServerModel, scanDoneRate float64, playSafe bool, chsLeft int) {
	preset.Ciphers = nil
	model.ScanKnownCipher = false
	c.scanForPreference = c.preferClient == nil && (c.isDone || scanDoneRate > 0.4) && len(model.CipherPrio) > 1

	if playSafe && c.preferClient == nil && len(model.CipherPrio) > 1 {
		// If we have to play safe anyway we can also scan for preference
		c.scanForPreference = true
	}

	for i := range c.ScanCiphers {
		scanned := false
		for j := range model.CipherPrio {
			if c.ScanCiphers[i] == model.CipherPrio[j] {
				scanned = true
			}
		}
		addCipher := !scanned || (playSafe && !c.scanForPreference)
		if addCipher && (!c.scanNo13 || !is13(c.ScanCiphers[i])) {
			preset.Ciphers = append(preset.Ciphers, c.ScanCiphers[i])
		}
	}
	if c.scanForPreference {
		preset.Ciphers = append(preset.Ciphers, c.lastCipher)
		is13Cipher := is13(c.lastCipher)
		for _, cipher := range model.CipherPrio {
			if is13Cipher && is13(cipher) {
				preset.Ciphers = append(preset.Ciphers, cipher)
				break
			} else if !is13Cipher && !is13(cipher) {
				preset.Ciphers = append(preset.Ciphers, cipher)
				break
			}
		}
		if preset.Ciphers[len(preset.Ciphers)-1] == c.lastCipher {
			c.preferenceImpossible = true
		}
	}
	tls13 := false
	for _, cipher := range preset.Ciphers {
		if is13(cipher) {
			tls13 = true
		}
	}
	if tls13 {
		preset.Version = tls.VersionTLS13
	}
}

func (c *CipherTask) Done(model *results.ServerModel) bool {
	if model.CipherScanComplete {
		c.isDone = true
	}
	if model.ReEnableCipherScan {
		c.isDone = false
		model.CipherScanComplete = false
		model.ReEnableCipherScan = false
	}
	return c.isDone && (c.preferClient != nil || len(model.CipherPrio) <= 1 || c.preferenceImpossible)
}

func (c *CipherTask) ResolveError(model *results.ServerModel) (learnedSomething bool) {
	if !c.scanNo13 {
		c.scanNo13 = true
		learnedSomething = true
	} else if !c.unconfiguredCipher {
		learnedSomething = !c.isDone
		c.isDone = true
		model.CipherScanComplete = true
	}
	if c.errorBehavior != "" {
		if model.CipherError != nil && c.errorBehavior != *model.CipherError {
			log.Debug().Str("ErrorBehavior", c.errorBehavior).Str("OldError", *model.CipherError).Msg("Contradicting Cipher Error Behaviors")
		}
		e := c.errorBehavior
		model.CipherError = &e
	}
	return
}

func (c *CipherTask) MergeData(state tls.ConnectionState, model *results.ServerModel, preset *tls.ClientHelloPreset, err error) (errorCouldBeMe bool, learnedSomething bool) {
	c.unconfiguredCipher = false
	c.errorBehavior = ""
	if state.ServerHello != nil {
		lastCipher := c.lastCipher
		c.lastCipher = state.ServerHello.CipherSuite
		addCipher := true
		for _, s := range model.CipherPrio {
			// same cipher could be caused by scanForPreference or other task
			if s == c.lastCipher {
				addCipher = false
			}
		}

		didSentCipher := false
		for _, s := range preset.Ciphers {
			if s == c.lastCipher {
				didSentCipher = true
			}
		}
		if !didSentCipher {
			model.IgnoresCipher = misc.NewTrue()
		}

		if addCipher {
			model.CipherPrio = append(model.CipherPrio, c.lastCipher)
			learnedSomething = true
		}
		if c.scanForPreference && model.PreferClientCipher == nil {
			if lastCipher == c.lastCipher {
				c.preferClient = misc.NewTrue()
			} else {
				c.preferClient = misc.NewFalse()
			}
			learnedSomething = learnedSomething || model.PreferClientCipher == nil
			model.PreferClientCipher = c.preferClient
		}
		if state.ServerHello.Vers <= tls.VersionTLS12 && state.ServerHello.SupportedVersion != tls.VersionTLS13 {
			c.scanNo13 = true
		}
	} else if !model.ScanKnownCipher {
		for _, e := range state.RecvAlerts {
			if e == 40 && len(model.CipherPrio) > 0 {
				errorCouldBeMe = true
				c.errorBehavior = "Alert"
			}
		}
		if strangeErrorHandlingPossible(err) {
			errorCouldBeMe = true
			c.errorBehavior = "TCP"
		}
		if len(state.SendAlerts) > 0 && (err == nil || !strings.Contains(err.Error(), "unsupported curve")) {
			errorCouldBeMe = true
		}
	}

	if err != nil && strings.Contains(err.Error(), "unconfigured cipher suite") {
		errorCouldBeMe = true
		c.unconfiguredCipher = true
	}

	if model.PreferClientCipher == nil {
		var ciphers13 []uint16
		var ciphers []uint16
		for _, cipher := range model.CipherPrio {
			if is13(cipher) {
				ciphers13 = append(ciphers13, cipher)
			} else {
				ciphers = append(ciphers, cipher)
			}
		}
		if isOrderInconsistent(c.ScanCiphers, ciphers13) || isOrderInconsistent(c.ScanCiphers, ciphers) {
			model.PreferClientCipher = misc.NewFalse()
			c.preferClient = model.PreferClientCipher
			learnedSomething = true
		}
	}
	return
}

func strangeErrorHandlingPossible(err error) bool {
	return err != nil && !strings.Contains(err.Error(), "timeout") && (strings.Contains(err.Error(), "tcp") || strings.Contains(err.Error(), "EOF"))
}

func isOrderInconsistent(scanned []uint16, observed []uint16) bool {
	i := 0
	j := 0
	for j < len(observed) {
		if scanned[i] == observed[j] {
			i++
			j++
		} else {
			i++
		}
		if i >= len(scanned) && j < len(observed) {
			return true
		}
	}
	return false
}

func is13(cipher uint16) bool {
	return cipher >= 0x1300 && cipher <= 0x1305
}

func (c *CipherTask) PostProcess(model *results.ServerModel) {
	if model.PreferClientCipher != nil && *model.PreferClientCipher {
		sort.Slice(model.CipherPrio, func(i, j int) bool {
			return model.CipherPrio[i] < model.CipherPrio[j]
		})
	}
	if c.isDone && len(model.CipherPrio) > 0 {
		model.CipherDone = misc.NewTrue()
	}
}
