// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"math"
	"strconv"
	"strings"
	"time"

	gnmipb "github.com/ctlplne/probectl/internal/gen/gnmi"
)

func opticalModelOrigin(origin string) bool {
	switch origin {
	case "", "openconfig", "openconfig-platform", "openconfig-platform-transceiver", "openconfig-terminal-device":
		return true
	}
	return false
}

// Read concrete OpenConfig containers, not a sensor's human-readable name.
// Component/channel keys are retained independently of interface identity.
func (c *gnmiCollector) normalizeOptical(n *gnmipb.Notification, update *gnmipb.Update, elems []*gnmipb.PathElem, at time.Time) (Metric, bool) {
	if !opticalModelOrigin(n.GetPrefix().GetOrigin()) || !opticalModelOrigin(update.GetPath().GetOrigin()) {
		return Metric{}, false
	}
	names := make([]string, len(elems))
	for i, elem := range elems {
		name := elem.GetName()
		if prefix, local, qualified := strings.Cut(name, ":"); qualified {
			if !opticalModelOrigin(prefix) || prefix == "" || prefix == "openconfig" {
				return Metric{}, false
			}
			name = local
		}
		names[i] = name
	}
	if len(names) < 5 || names[0] != "components" || names[1] != "component" || names[len(names)-1] != "instant" {
		return Metric{}, false
	}
	component := elems[1].GetKey()["name"]
	if component == "" {
		return Metric{}, false
	}
	channel, measure := "", ""
	scope := names[2]
	switch {
	case len(names) == 5 && scope == "state" && names[3] == "temperature":
		measure = "temperature"
	case len(names) == 6 && (scope == "transceiver" || scope == "optical-channel") && names[3] == "state":
		measure = names[4]
	case len(names) == 8 && scope == "transceiver" && names[3] == "physical-channels" && names[4] == "channel" && names[5] == "state":
		index, err := strconv.ParseUint(elems[4].GetKey()["index"], 10, 32)
		if err != nil {
			return Metric{}, false
		}
		channel, measure = strconv.FormatUint(index, 10), names[6]
	default:
		return Metric{}, false
	}
	name, unit := "", ""
	switch measure {
	case "input-power":
		name, unit = MetricOpticalInputDBM, "dBm"
	case "output-power":
		name, unit = MetricOpticalOutputDBM, "dBm"
	case "laser-bias-current":
		if scope != "transceiver" {
			return Metric{}, false
		}
		name, unit = MetricOpticalBiasMA, "mA"
	case "supply-voltage":
		if scope != "transceiver" || channel != "" {
			return Metric{}, false
		}
		name, unit = MetricOpticalVoltage, "V"
	case "temperature":
		name, unit = MetricSensorCelsius, "celsius"
	default:
		return Metric{}, false
	}
	value, ok := opticalScalarValue(update.GetVal())
	if !ok {
		return Metric{}, false // An unsupported value is never a zero sample.
	}
	return Metric{TenantID: c.tenant, AgentID: c.agent, Device: c.dev.Address, DeviceName: targetName(n), Source: SourceGNMI,
		Component: component, PhysicalChannel: channel, Name: name, Value: value, Unit: unit, At: at}, true
}

// Device gauges use the existing float64 TSDB representation. gNMI decimal
// mantissas are scaled once; OpenConfig's fraction-digits do not imply another
// division by100. Reflection reads legacy wire variants without generating
// deprecated protocol types or adding a second gNMI dependency.
func opticalScalarValue(value *gnmipb.TypedValue) (float64, bool) {
	if value == nil {
		return 0, false
	}
	var number float64
	var err error
	nonzero := false
	switch raw := value.GetValue().(type) {
	case *gnmipb.TypedValue_DoubleVal:
		number = raw.DoubleVal
	case *gnmipb.TypedValue_IntVal:
		number = float64(raw.IntVal)
	case *gnmipb.TypedValue_UintVal:
		number = float64(raw.UintVal)
	case *gnmipb.TypedValue_StringVal:
		number, err = strconv.ParseFloat(raw.StringVal, 64)
		mantissa, _, _ := strings.Cut(raw.StringVal, "e")
		mantissa, _, _ = strings.Cut(mantissa, "E")
		nonzero = strings.ContainsAny(mantissa, "123456789")
	default:
		message := value.ProtoReflect()
		field := message.WhichOneof(message.Descriptor().Oneofs().ByName("value"))
		if field == nil {
			return 0, false
		}
		switch field.Name() {
		case "float_val":
			number = message.Get(field).Float()
		case "decimal_val":
			decimal := message.Get(field).Message()
			if !decimal.IsValid() {
				return 0, false
			}
			fields := decimal.Descriptor().Fields()
			digits, precision := decimal.Get(fields.ByName("digits")).Int(), decimal.Get(fields.ByName("precision")).Uint()
			number, err = strconv.ParseFloat(strconv.FormatInt(digits, 10)+"e-"+strconv.FormatUint(precision, 10), 64)
			nonzero = digits != 0
		default:
			return 0, false
		}
	}
	return number, err == nil && !math.IsNaN(number) && !math.IsInf(number, 0) && !(nonzero && number == 0)
}
