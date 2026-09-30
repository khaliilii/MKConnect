//go:build !no_xray

package engine

import (
	"bytes"

	"github.com/xtls/xray-core/core"
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
