package dissectls

import (
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
	"strings"
)

var supportedVersions13 = []uint16{tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10}

type VersionTask struct {
	isDone          bool
	modifiedVersion bool
	lastVersion     uint16
	errorBehavior   string
	DetailedScan    bool
}

func (c *VersionTask) SetCHValues(preset *tls.ClientHelloPreset, model *results.ServerModel, scanDoneRate float64, playSafe bool, chsLeft int) {

	// Set to highest version the server supports, if not set to 1.3 by other tasks
	var maxVersion uint16
	if preset.Version < tls.VersionTLS13 {

		// Use lowest version we know of, because we know only of the highest version or are rescanning on a lower version
		// Not 1.3 per default
		if model.VersionSSLv3 != nil && *model.VersionSSLv3 == "True" {
			maxVersion = tls.VersionSSL30
		} else if model.VersionTLS10 != nil && *model.VersionTLS10 == "True" {
			maxVersion = tls.VersionTLS10
		} else if model.VersionTLS11 != nil && *model.VersionTLS11 == "True" {
			maxVersion = tls.VersionTLS11
		} else if model.VersionTLS12 != nil && *model.VersionTLS12 == "True" {
			maxVersion = tls.VersionTLS12
		}

		// If I do not know anything use highest versions
		if maxVersion == 0 {
			c.modifiedVersion = true
			maxVersion = tls.VersionTLS12
			if model.VersionTLS12 != nil && *model.VersionTLS12 != "True" {
				maxVersion = tls.VersionTLS11
				if model.VersionTLS11 != nil && *model.VersionTLS11 != "True" {
					maxVersion = tls.VersionTLS10
					if model.VersionTLS10 != nil && *model.VersionTLS10 != "True" {
						maxVersion = tls.VersionTLS13
					}
				}
			}
		}
		preset.Version = maxVersion
	}

	if !playSafe && !c.isDone {
		scansLeft := 0
		if model.VersionTLS12 == nil {
			scansLeft++
		}
		if model.VersionTLS11 == nil {
			scansLeft++
		}
		if model.VersionTLS10 == nil {
			scansLeft++
		}
		if scansLeft > 0 && (model.CipherScanComplete || scansLeft >= chsLeft) {
			c.modifiedVersion = true
			c.DetailedScan = false
			model.CipherScanComplete = true
			preset.Ciphers = ScannerSupported12Ciphers
			if model.VersionTLS12 == nil {
				preset.Version = tls.VersionTLS12
			} else if model.VersionTLS11 == nil {
				preset.Version = tls.VersionTLS11
			} else if model.VersionTLS10 == nil {
				preset.Version = tls.VersionTLS10
			}
		}
	}

	c.lastVersion = preset.Version
	if preset.Version == tls.VersionTLS13 {
		// Configure 1.3
		preset.Version = tls.VersionTLS12
		preset.SupportedVersions = supportedVersions13
		if len(preset.SupportedGroups) == 0 {
			preset.SupportedGroups = ScannerSupportedGroups
			preset.KeyShares = 1
		}
	}
}

func (c *VersionTask) Done(*results.ServerModel) bool {
	return false
}

func (c *VersionTask) inferVersion(model *results.ServerModel, value string) (learnedSomething bool) {
	if model.VersionTLS10 == nil && c.lastVersion == tls.VersionTLS10 {
		model.VersionTLS10 = &value
		learnedSomething = true
	}
	if model.VersionTLS11 == nil && c.lastVersion == tls.VersionTLS11 {
		model.VersionTLS11 = &value
		learnedSomething = true
	}
	if model.VersionTLS12 == nil && c.lastVersion == tls.VersionTLS12 {
		model.VersionTLS12 = &value
		learnedSomething = true
	}
	if model.VersionTLS13 == nil && c.lastVersion == tls.VersionTLS13 {
		model.VersionTLS13 = &value
		learnedSomething = true
	}
	if model.VersionSSLv3 == nil && c.lastVersion == tls.VersionSSL30 {
		model.VersionSSLv3 = &value
		learnedSomething = true
	}
	return
}

func (c *VersionTask) ResolveError(model *results.ServerModel) (learnedSomething bool) {
	learnedSomething = c.inferVersion(model, "False")
	if model.VersionTLS10 != nil && model.VersionTLS11 != nil && model.VersionTLS12 != nil && model.VersionTLS13 != nil {
		c.isDone = true
	}
	if c.errorBehavior != "" {
		if model.VersionError != nil && c.errorBehavior != *model.VersionError {
			log.Debug().Str("ErrorBehavior", c.errorBehavior).Str("OldError", *model.VersionError).Msg("Contradicting Version Error Behaviors")
		}
		e := c.errorBehavior
		model.VersionError = &e
	}
	return
}

func (c *VersionTask) MergeData(state tls.ConnectionState, model *results.ServerModel, preset *tls.ClientHelloPreset, err error) (errorCouldBeMe bool, learnedSomething bool) {
	c.errorBehavior = ""
	if c.isDone {
		return
	}
	if state.ServerHello != nil {
		v := "True"
		switch state.ServerHello.Vers {
		case tls.VersionTLS10:
			learnedSomething = model.VersionTLS10 == nil
			model.VersionTLS10 = &v
		case tls.VersionTLS11:
			learnedSomething = model.VersionTLS11 == nil
			model.VersionTLS11 = &v
		case tls.VersionSSL30:
			learnedSomething = model.VersionSSLv3 == nil
			model.VersionSSLv3 = &v
		case tls.VersionTLS12:
			if state.ServerHello.SupportedVersion == tls.VersionTLS13 {
				learnedSomething = model.VersionTLS13 == nil
				model.VersionTLS13 = &v
			} else {
				learnedSomething = model.VersionTLS12 == nil
				model.VersionTLS12 = &v
			}
		}
		learnedSomething = c.inferVersion(model, "Downgrade") || learnedSomething
		if learnedSomething && c.DetailedScan {
			model.ReEnableCipherScan = true
		}
	} else if c.modifiedVersion {
		for _, e := range state.RecvAlerts {
			if e == 40 || e == 70 || e == 80 {
				errorCouldBeMe = true
				c.errorBehavior = "Alert"
			}
		}
		if strangeErrorHandlingPossible(err) {
			c.errorBehavior = "TCP"
			errorCouldBeMe = true
		}
		if len(state.SendAlerts) > 0 && (err == nil || (!strings.Contains(err.Error(), "unconfigured cipher") && !strings.Contains(err.Error(), "unconfigured cipher suite"))) {
			errorCouldBeMe = true
		}
		if err != nil && strings.Contains(err.Error(), "first record does not look like a TLS handshake") {
			c.errorBehavior = "No TLS"
			learnedSomething = c.inferVersion(model, "No TLS") || learnedSomething
			errorCouldBeMe = true
		}
	}

	if model.VersionTLS10 != nil && model.VersionTLS11 != nil && model.VersionTLS12 != nil && model.VersionTLS13 != nil {
		c.isDone = true
	}

	return
}

func (c *VersionTask) PostProcess(*results.ServerModel) {}
