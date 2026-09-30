//go:build !no_xray

package engine

import (
	"bytes"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all" // register all protocols and transports
)

func init() { startXray = newXray }

type xrayEngine struct{ instance *core.Instance }

func newXray(config []byte) (Engine, error) {
	cfg, err := serial.LoadJSONConfig(bytes.NewReader(config))
	if err != nil {
		return nil, err
	}
	instance, err := core.New(cfg)
	if err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		return nil, err
	}
	return &xrayEngine{instance: instance}, nil
}

func (e *xrayEngine) Close() error { return e.instance.Close() }

func (e *xrayEngine) Traffic() (up, down int64) {
	m, ok := e.instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return 0, 0
	}
	// Counters are registered lazily on the first proxied connection.
	value := func(name string) int64 {
		if c := m.GetCounter(name); c != nil {
			return c.Value()
		}
		return 0
	}
	return value("outbound>>>" + tagProxy + ">>>traffic>>>uplink"), value("outbound>>>" + tagProxy + ">>>traffic>>>downlink")
}
