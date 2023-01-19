package dissectls

import (
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
	"golang.org/x/crypto/cryptobyte"
)

type HeartbeatTask struct {
	is2ndRun bool
	isDone   bool
}

func (c *HeartbeatTask) SetCHValues(preset *tls.ClientHelloPreset, model *results.ServerModel, scanDoneRate float64, playSafe bool, chsLeft int) {
	preset.Heartbeat = 1
	if c.is2ndRun {
		preset.Heartbeat = 2
	}
}

func (c *HeartbeatTask) Done(*results.ServerModel) bool {
	return c.isDone
}

func (c *HeartbeatTask) ResolveError(*results.ServerModel) (learnedSomething bool) { return }

func (c *HeartbeatTask) MergeData(state tls.ConnectionState, model *results.ServerModel, preset *tls.ClientHelloPreset, err error) (errorCouldBeMe bool, learnedSomething bool) {
	for _, extSlice := range [][]tls.Extension{state.ServerExtensions, state.ServerEncryptedExtensions} {
		for _, ext := range extSlice {
			if ext.Extension == tls.ExtensionHeartbeat {
				extData := cryptobyte.String(ext.Data)
				var mode uint8
				if !extData.ReadUint8(&mode) {
					continue
				}
				add := true
				for _, e := range model.Heartbeat {
					if e == mode {
						add = false
					}
				}
				if add {
					model.Heartbeat = append(model.Heartbeat, mode)
					learnedSomething = true
				}
			}
		}
	}
	if state.ServerHello != nil {
		if c.is2ndRun {
			c.isDone = true
		}
		c.is2ndRun = true
	}
	return
}

func (c *HeartbeatTask) PostProcess(*results.ServerModel) {}
