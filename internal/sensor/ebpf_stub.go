// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package sensor

import "github.com/samyxo-bv/ringwall/internal/config"

func newEBPFSensor(_ config.SensorConfig) (Sensor, error) {
	return nil, ErrUnsupportedPlatform
}

func newProcfsSensor(_ config.SensorConfig) (Sensor, error) {
	return nil, ErrUnsupportedPlatform
}
