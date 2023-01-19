package dissectls

import (
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
)

type FallbackTask struct {
	scan bool
	done bool
}

func (c *FallbackTask) SetCHValues(preset *tls.ClientHelloPreset, model *results.ServerModel, scanDoneRate float64, playSafe bool, chsLeft int) {
	c.scan = false
	var maxSupport uint16
	if model.VersionTLS13 != nil && *model.VersionTLS13 == "True" {
		maxSupport = tls.VersionTLS13
	} else if model.VersionTLS12 != nil && *model.VersionTLS12 == "True" {
		maxSupport = tls.VersionTLS12
	} else if model.VersionTLS11 != nil && *model.VersionTLS11 == "True" {
		maxSupport = tls.VersionTLS11
	} else if model.VersionTLS10 != nil && *model.VersionTLS10 == "True" {
		maxSupport = tls.VersionTLS10
	}

	if preset.Version == tls.VersionTLS12 && maxSupport == tls.VersionTLS13 && preset.SupportedVersions == nil {
		c.scan = true
	} else if preset.Version == tls.VersionTLS11 && preset.Version < maxSupport {
		c.scan = true
	} else if preset.Version == tls.VersionTLS10 && preset.Version < maxSupport {
		c.scan = true
	}

	if c.scan {
		preset.Ciphers = append(preset.Ciphers, tls.TLS_FALLBACK_SCSV)
	}
}

func (c *FallbackTask) Done(model *results.ServerModel) bool {
	return c.done
}

func (c *FallbackTask) ResolveError(*results.ServerModel) (learnedSomething bool) { return }

func (c *FallbackTask) MergeData(state tls.ConnectionState, model *results.ServerModel, preset *tls.ClientHelloPreset, err error) (errorCouldBeMe bool, learnedSomething bool) {
	if c.scan {
		for _, a := range state.RecvAlerts {
			if a == 86 {
				errorCouldBeMe = true
				c.done = true
				if model.InappropriateFallbackSupport != nil {
					log.Error().Bool("Support", *model.InappropriateFallbackSupport).Msg("Contradicting Fallback Support")
				}
				learnedSomething = model.InappropriateFallbackSupport == nil
				model.InappropriateFallbackSupport = misc.NewTrue()
				return
			}
		}
		if state.ServerHello != nil {
			learnedSomething = model.InappropriateFallbackSupport == nil
			model.InappropriateFallbackSupport = misc.NewFalse()
		}
	}
	return
}

func (c *FallbackTask) PostProcess(*results.ServerModel) {}
