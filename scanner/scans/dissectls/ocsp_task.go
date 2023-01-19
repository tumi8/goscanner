package dissectls

import (
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
)

// OCSPTask Benefit as explicit task? /**
type OCSPTask struct {
}

func (c *OCSPTask) SetCHValues(preset *tls.ClientHelloPreset, model *results.ServerModel, scanDoneRate float64, playSafe bool, chsLeft int) {
	preset.StatusRequest = true
}

func (c *OCSPTask) Done(model *results.ServerModel) bool {
	return false
}

func (c *OCSPTask) ResolveError(*results.ServerModel) (learnedSomething bool) { return }

func (c *OCSPTask) MergeData(state tls.ConnectionState, model *results.ServerModel, preset *tls.ClientHelloPreset, err error) (errorCouldBeMe bool, learnedSomething bool) {
	for _, extSlice := range [][]tls.Extension{state.ServerExtensions, state.ServerEncryptedExtensions, state.CertificateExtensions} {
		for _, ext := range extSlice {
			if ext.Extension == tls.ExtensionStatusRequest {
				learnedSomething = model.StatusRequest == nil
				model.StatusRequest = misc.NewTrue()
			}
		}
	}
	return
}

func (c *OCSPTask) PostProcess(*results.ServerModel) {}
