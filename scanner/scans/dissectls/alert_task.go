package dissectls

import (
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
)

type AlertTask struct {
	alerts []tls.Alert
}

func (c *AlertTask) SetCHValues(preset *tls.ClientHelloPreset, model *results.ServerModel, scanDoneRate float64, playSafe bool, chsLeft int) {
}

func (c *AlertTask) Done(model *results.ServerModel) bool {
	return false
}

func (c *AlertTask) ResolveError(*results.ServerModel) (learnedSomething bool) { return }

func (c *AlertTask) MergeData(state tls.ConnectionState, model *results.ServerModel, preset *tls.ClientHelloPreset, err error) (errorCouldBeMe bool, learnedSomething bool) {
	for _, a := range state.RecvAlerts {
		model.AlertSequence = append(model.AlertSequence, a)
		present := false
		for _, a2 := range c.alerts {
			if a == a2 {
				present = true
			}
		}
		if !present {
			c.alerts = append(c.alerts, a)
			learnedSomething = true
		}
	}
	return
}

func (c *AlertTask) PostProcess(*results.ServerModel) {}
