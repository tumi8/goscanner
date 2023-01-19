package dissectls

import (
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
	"golang.org/x/crypto/cryptobyte"
	"sort"
)

type AlpnTask struct {
	ALPNs             []string
	lastALPN          string
	scanForPreference bool
	isDone            bool
	preferClient      *bool
	errorBehavior     string
}

var ScannerALPN = []string{"h2", "http/1.1", "http/1.0"}

func (c *AlpnTask) SetCHValues(preset *tls.ClientHelloPreset, model *results.ServerModel, scanDoneRate float64, playSafe bool, chsLeft int) {
	c.scanForPreference = c.preferClient == nil && (c.isDone || len(model.AlpnPrio) >= len(c.ALPNs) || scanDoneRate > 0.5) && len(model.AlpnPrio) > 1

	if playSafe && c.preferClient == nil && len(model.AlpnPrio) > 1 {
		// If we have to play safe anyway we can also scan for preference
		c.scanForPreference = true
	}

	preset.Alpn = nil
	for i := range c.ALPNs {
		scanned := false
		for j := range model.AlpnPrio {
			if c.ALPNs[i] == model.AlpnPrio[j] {
				scanned = true
			}
		}
		if !scanned || (playSafe && !c.scanForPreference) {
			preset.Alpn = append(preset.Alpn, c.ALPNs[i])
		}
	}
	if c.scanForPreference {
		preset.Alpn = append(preset.Alpn, c.lastALPN, model.AlpnPrio[0])
	}
}

func (c *AlpnTask) Done(model *results.ServerModel) bool {
	if c.isDone && len(model.AlpnPrio) <= 1 {
		// Preference Client Impossible to compute
		return true
	}
	return c.preferClient != nil && (c.isDone || len(model.AlpnPrio) >= len(c.ALPNs))
}

func (c *AlpnTask) ResolveError(model *results.ServerModel) (learnedSomething bool) {
	c.isDone = true
	learnedSomething = true
	if c.errorBehavior != "" {
		if model.AlpnError != nil && c.errorBehavior != *model.AlpnError {
			log.Debug().Str("ErrorBehavior", c.errorBehavior).Str("OldError", *model.AlpnError).Msg("Contradicting AlpnError Behaviors")
		}
		e := c.errorBehavior
		model.AlpnError = &e
	}
	return
}

func (c *AlpnTask) MergeData(state tls.ConnectionState, model *results.ServerModel, preset *tls.ClientHelloPreset, err error) (errorCouldBeMe bool, learnedSomething bool) {
	c.errorBehavior = ""
	for _, e := range state.RecvAlerts {
		if e == 40 || e == 80 {
			errorCouldBeMe = true
			c.errorBehavior = "Alert"
		}
	}

	if strangeErrorHandlingPossible(err) {
		errorCouldBeMe = true
		c.errorBehavior = "TCP"
	}

	for _, extSlice := range [][]tls.Extension{state.ServerExtensions, state.ServerEncryptedExtensions} {
		for _, ext := range extSlice {
			if ext.Extension == tls.ExtensionALPN {
				extData := cryptobyte.String(ext.Data)
				var protoList cryptobyte.String
				if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
					continue
				}
				var proto cryptobyte.String
				if !protoList.ReadUint8LengthPrefixed(&proto) ||
					proto.Empty() || !protoList.Empty() {
					continue
				}
				alpn := string(proto)

				addALPN := true
				for _, s := range model.AlpnPrio {
					// same cipher could be caused by scanForPreference or other task
					if s == alpn {
						addALPN = false
					}
				}
				didSentALPN := false
				for _, s := range preset.Alpn {
					if s == alpn {
						didSentALPN = true
					}
				}
				if !didSentALPN {
					model.IgnoresAlpn = misc.NewTrue()
				}

				if addALPN {
					model.AlpnPrio = append(model.AlpnPrio, alpn)
					learnedSomething = true
				}
				if c.scanForPreference && model.PreferClientAlpn == nil {
					if alpn == c.lastALPN {
						c.preferClient = misc.NewTrue()
					} else {
						c.preferClient = misc.NewFalse()
					}
					model.PreferClientAlpn = c.preferClient
					learnedSomething = true
				}
				c.lastALPN = alpn
			}
		}
	}

	if !learnedSomething {
		if model.AlpnError == nil && !c.isDone {
			e := "Ignore"
			model.AlpnError = &e
		}
		c.isDone = true
		if c.scanForPreference && model.PreferClientAlpn == nil {
			// Should be impossible with proper servers, but in case they behave strange we stop ALPN scanning
			c.preferClient = misc.NewFalse()
		}
	}

	if model.PreferClientAlpn == nil {
		i := 0
		j := 0
		for j < len(model.AlpnPrio) {
			if c.ALPNs[i] == model.AlpnPrio[j] {
				i++
				j++
			} else {
				i++
			}
			if i >= len(c.ALPNs) && j < len(model.AlpnPrio) {
				model.PreferClientAlpn = misc.NewFalse()
				c.preferClient = model.PreferClientAlpn
				learnedSomething = true
				break
			}
		}
	}

	return
}

func (c *AlpnTask) PostProcess(model *results.ServerModel) {
	if model.PreferClientAlpn != nil && *model.PreferClientAlpn {
		sort.Strings(model.AlpnPrio)
	}
}
