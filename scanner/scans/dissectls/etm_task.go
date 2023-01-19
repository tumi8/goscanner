package dissectls

import (
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
)

type ETMTask struct {
	scanning bool
}

func (c *ETMTask) SetCHValues(preset *tls.ClientHelloPreset, model *results.ServerModel, scanDoneRate float64, playSafe bool, chsLeft int) {
	c.scanning = false
	if !preset.ExtendedMasterSecret && model.EncryptThenMac == nil && !playSafe {
		c.scanning = true
		preset.EncryptThenMac = true
	}
	preset.EncryptThenMac = model.EncryptThenMac == nil && !playSafe
}

func (c *ETMTask) Done(model *results.ServerModel) bool {
	return model.EncryptThenMac != nil
}

func (c *ETMTask) ResolveError(*results.ServerModel) (learnedSomething bool) { return }

func (c *ETMTask) MergeData(state tls.ConnectionState, model *results.ServerModel, preset *tls.ClientHelloPreset, err error) (errorCouldBeMe bool, learnedSomething bool) {
	for _, extSlice := range [][]tls.Extension{state.ServerExtensions, state.ServerEncryptedExtensions, state.CertificateExtensions} {
		for _, ext := range extSlice {
			if ext.Extension == tls.ExtensionEncryptThenMac {
				errorCouldBeMe = true
				learnedSomething = true
				model.EncryptThenMac = misc.NewTrue()
			}
		}
	}
	if model.EncryptThenMac == nil && state.ServerHello != nil && state.Version < tls.VersionTLS13 && c.scanning {
		learnedSomething = true
		model.EncryptThenMac = misc.NewFalse()
	}
	return
}

func (c *ETMTask) PostProcess(*results.ServerModel) {}
