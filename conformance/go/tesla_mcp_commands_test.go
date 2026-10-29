// tesla-mcp command conformance test, compiled inside Tesla's vehicle-command
// module.
//
// conformance/run.sh copies this file into pkg/vehicle of a pinned checkout of
// github.com/teslamotors/vehicle-command. It swaps the Vehicle's dispatcher
// for one that records the first message instead of sending it, calls Tesla's
// own command methods (HonkHorn, SetSeatHeater, ...), and requires every
// payload in test/vectors/vcp-commands.json to be byte-identical to what
// Tesla's code built and to decode to the same message. The TypeScript tests
// assert the same file, so a pass proves the Worker builds each command
// exactly as Tesla's client does.

package vehicle

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/teslamotors/vehicle-command/internal/dispatcher"
	"github.com/teslamotors/vehicle-command/pkg/connector"
	"github.com/teslamotors/vehicle-command/pkg/protocol"
	carserver "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/carserver"
	universal "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/vcsec"
)

var errCaptured = errors.New("tesla-mcp: message captured")

// captureSender records the first message a command sends and fails the send,
// so the command returns without waiting for a reply.
type captureSender struct {
	message *universal.RoutableMessage
}

func (c *captureSender) Start(context.Context) error { return nil }
func (c *captureSender) Stop()                       {}
func (c *captureSender) Send(_ context.Context, message *universal.RoutableMessage, _ connector.AuthMethod) (protocol.Receiver, error) {
	if c.message == nil {
		c.message = proto.Clone(message).(*universal.RoutableMessage)
	}
	return nil, errCaptured
}
func (c *captureSender) StartSessions(context.Context, []universal.Domain) error { return nil }
func (c *captureSender) Cache() []dispatcher.CacheEntry                          { return nil }
func (c *captureSender) LoadCache([]dispatcher.CacheEntry) error                 { return nil }
func (c *captureSender) RetryInterval() time.Duration                            { return time.Millisecond }
func (c *captureSender) SetMaxLatency(time.Duration)                             {}

// fleetConnector satisfies connector.FleetAPIConnector, which SetPINToDrive
// requires. It is never used to send anything.
type fleetConnector struct{ connector.FleetAPIConnector }

// schemaCommands are vectors for commands Tesla's Go client has no method for
// (it only exposes an absolute sunroof level). They are checked against
// Tesla's generated carserver schema instead of a Vehicle method.
var schemaCommands = map[string]*carserver.Action{
	"sunroof_vent": sunroofAction(&carserver.VehicleControlSunroofOpenCloseAction{
		Action: &carserver.VehicleControlSunroofOpenCloseAction_Vent{Vent: &carserver.Void{}},
	}),
	"sunroof_close": sunroofAction(&carserver.VehicleControlSunroofOpenCloseAction{
		Action: &carserver.VehicleControlSunroofOpenCloseAction_Close{Close: &carserver.Void{}},
	}),
}

func sunroofAction(sunroof *carserver.VehicleControlSunroofOpenCloseAction) *carserver.Action {
	return &carserver.Action{ActionMsg: &carserver.Action_VehicleAction{VehicleAction: &carserver.VehicleAction{
		VehicleActionMsg: &carserver.VehicleAction_VehicleControlSunroofOpenCloseAction{
			VehicleControlSunroofOpenCloseAction: sunroof,
		},
	}}}
}

// teslaCalls maps each vector id to the Tesla method call that must build its
// payload. The arguments are the vector's params, written out.
var teslaCalls = map[string]func(context.Context, *Vehicle) error{
	"door_lock":           func(c context.Context, v *Vehicle) error { return v.Lock(c) },
	"door_unlock":         func(c context.Context, v *Vehicle) error { return v.Unlock(c) },
	"remote_start_drive":  func(c context.Context, v *Vehicle) error { return v.RemoteDrive(c) },
	"auto_secure_vehicle": func(c context.Context, v *Vehicle) error { return v.AutoSecureVehicle(c) },
	"trunk_open":          func(c context.Context, v *Vehicle) error { return v.OpenTrunk(c) },
	"trunk_close":         func(c context.Context, v *Vehicle) error { return v.CloseTrunk(c) },
	"frunk_open":          func(c context.Context, v *Vehicle) error { return v.OpenFrunk(c) },
	"tonneau_open":        func(c context.Context, v *Vehicle) error { return v.OpenTonneau(c) },
	"tonneau_close":       func(c context.Context, v *Vehicle) error { return v.CloseTonneau(c) },
	"tonneau_stop":        func(c context.Context, v *Vehicle) error { return v.StopTonneau(c) },

	"auto_conditioning_start": func(c context.Context, v *Vehicle) error { return v.ClimateOn(c) },
	"auto_conditioning_stop":  func(c context.Context, v *Vehicle) error { return v.ClimateOff(c) },
	"set_temps":               func(c context.Context, v *Vehicle) error { return v.ChangeClimateTemp(c, 21.5, 20) },
	"set_preconditioning_max_on_override": func(c context.Context, v *Vehicle) error {
		return v.SetPreconditioningMax(c, true, true)
	},
	"set_preconditioning_max_off": func(c context.Context, v *Vehicle) error { return v.SetPreconditioningMax(c, false, false) },
	"set_bioweapon_mode_on":       func(c context.Context, v *Vehicle) error { return v.SetBioweaponDefenseMode(c, true, false) },
	"set_cabin_overheat_protection_fan_only": func(c context.Context, v *Vehicle) error {
		return v.SetCabinOverheatProtection(c, true, true)
	},
	// CopActivationTemp is passed straight through as the Level: Medium = 2.
	"set_cop_temp_medium": func(c context.Context, v *Vehicle) error { return v.SetCabinOverheatProtectionTemperature(c, Level(2)) },
	"set_climate_keeper_mode_dog": func(c context.Context, v *Vehicle) error {
		return v.SetClimateKeeperMode(c, ClimateKeeperModeDog, true)
	},
	"set_climate_keeper_mode_off": func(c context.Context, v *Vehicle) error {
		return v.SetClimateKeeperMode(c, ClimateKeeperModeOff, false)
	},
	"remote_seat_heater_front_left_high": func(c context.Context, v *Vehicle) error {
		return v.SetSeatHeater(c, map[SeatPosition]Level{SeatFrontLeft: LevelHigh})
	},
	"remote_seat_heater_third_row_right_off": func(c context.Context, v *Vehicle) error {
		return v.SetSeatHeater(c, map[SeatPosition]Level{SeatThirdRowRight: LevelOff})
	},
	"remote_seat_cooler_front_right_low": func(c context.Context, v *Vehicle) error {
		return v.SetSeatCooler(c, LevelLow, SeatFrontRight)
	},
	"remote_auto_seat_climate_front_left_on": func(c context.Context, v *Vehicle) error {
		return v.AutoSeatAndClimate(c, []SeatPosition{SeatFrontLeft}, true)
	},
	"remote_steering_wheel_heater_on": func(c context.Context, v *Vehicle) error { return v.SetSteeringWheelHeater(c, true) },

	"charge_start":           func(c context.Context, v *Vehicle) error { return v.ChargeStart(c) },
	"charge_stop":            func(c context.Context, v *Vehicle) error { return v.ChargeStop(c) },
	"charge_standard":        func(c context.Context, v *Vehicle) error { return v.ChargeStandardRange(c) },
	"charge_max_range":       func(c context.Context, v *Vehicle) error { return v.ChargeMaxRange(c) },
	"set_charge_limit_80":    func(c context.Context, v *Vehicle) error { return v.ChangeChargeLimit(c, 80) },
	"set_charging_amps_16":   func(c context.Context, v *Vehicle) error { return v.SetChargingAmps(c, 16) },
	"charge_port_door_open":  func(c context.Context, v *Vehicle) error { return v.ChargePortOpen(c) },
	"charge_port_door_close": func(c context.Context, v *Vehicle) error { return v.ChargePortClose(c) },
	"set_scheduled_charging_on": func(c context.Context, v *Vehicle) error {
		return v.ScheduleCharging(c, true, 120*time.Minute)
	},
	"set_scheduled_departure": func(c context.Context, v *Vehicle) error {
		return v.ScheduleDeparture(c, 450*time.Minute, 360*time.Minute, ChargingPolicyWeekdays, ChargingPolicyAllDays)
	},
	"clear_scheduled_departure": func(c context.Context, v *Vehicle) error { return v.ClearScheduledDeparture(c) },
	"add_charge_schedule": func(c context.Context, v *Vehicle) error {
		return v.AddChargeSchedule(c, &ChargeSchedule{
			Id: 1700000000, Name: "Home", DaysOfWeek: 2 | 8 | 32,
			StartEnabled: true, StartTime: 1320, EndEnabled: true, EndTime: 360,
			OneTime: false, Enabled: true, Latitude: 37.5, Longitude: -122.25,
		})
	},
	"remove_charge_schedule": func(c context.Context, v *Vehicle) error { return v.RemoveChargeSchedule(c, 1700000000) },
	"batch_remove_charge_schedules_home_other": func(c context.Context, v *Vehicle) error {
		return v.BatchRemoveChargeSchedules(c, true, false, true)
	},
	"add_precondition_schedule": func(c context.Context, v *Vehicle) error {
		return v.AddPreconditionSchedule(c, &PreconditionSchedule{
			Id: 1700000001, DaysOfWeek: 1 | 64, PreconditionTime: 480,
			OneTime: true, Enabled: true, Latitude: -33.875, Longitude: 151.25,
		})
	},
	"remove_precondition_schedule": func(c context.Context, v *Vehicle) error {
		return v.RemovePreconditionSchedule(c, 1700000001)
	},
	"batch_remove_precondition_schedules_work": func(c context.Context, v *Vehicle) error {
		return v.BatchRemovePreconditionSchedules(c, false, true, false)
	},
	"set_low_power_mode_on":        func(c context.Context, v *Vehicle) error { return v.SetLowPowerMode(c, true) },
	"keep_accessory_power_mode_on": func(c context.Context, v *Vehicle) error { return v.SetKeepAccessoryPowerMode(c, true) },

	"adjust_volume_5_5":     func(c context.Context, v *Vehicle) error { return v.SetVolume(c, 5.5) },
	"adjust_volume_0":       func(c context.Context, v *Vehicle) error { return v.SetVolume(c, 0) },
	"media_volume_up":       func(c context.Context, v *Vehicle) error { return v.VolumeUp(c) },
	"media_volume_down":     func(c context.Context, v *Vehicle) error { return v.VolumeDown(c) },
	"media_toggle_playback": func(c context.Context, v *Vehicle) error { return v.ToggleMediaPlayback(c) },
	"media_next_fav":        func(c context.Context, v *Vehicle) error { return v.MediaNextFavorite(c) },
	"media_prev_fav":        func(c context.Context, v *Vehicle) error { return v.MediaPreviousFavorite(c) },
	"media_next_track":      func(c context.Context, v *Vehicle) error { return v.MediaNextTrack(c) },
	"media_prev_track":      func(c context.Context, v *Vehicle) error { return v.MediaPreviousTrack(c) },

	"honk_horn":    func(c context.Context, v *Vehicle) error { return v.HonkHorn(c) },
	"flash_lights": func(c context.Context, v *Vehicle) error { return v.FlashLights(c) },
	"window_vent":  func(c context.Context, v *Vehicle) error { return v.VentWindows(c) },
	"window_close": func(c context.Context, v *Vehicle) error { return v.CloseWindows(c) },

	"set_sentry_mode_on":          func(c context.Context, v *Vehicle) error { return v.SetSentryMode(c, true) },
	"set_sentry_mode_off":         func(c context.Context, v *Vehicle) error { return v.SetSentryMode(c, false) },
	"set_valet_mode_on":           func(c context.Context, v *Vehicle) error { return v.SetValetMode(c, true, "1234") },
	"set_valet_mode_off":          func(c context.Context, v *Vehicle) error { return v.SetValetMode(c, false, "") },
	"reset_valet_pin":             func(c context.Context, v *Vehicle) error { return v.ResetValetPin(c) },
	"set_pin_to_drive_on":         func(c context.Context, v *Vehicle) error { return v.SetPINToDrive(c, true, "4321") },
	"reset_pin_to_drive_pin":      func(c context.Context, v *Vehicle) error { return v.ResetPIN(c) },
	"clear_pin_to_drive_admin":    func(c context.Context, v *Vehicle) error { return v.ClearPINToDrive(c) },
	"speed_limit_activate":        func(c context.Context, v *Vehicle) error { return v.ActivateSpeedLimit(c, "1111") },
	"speed_limit_deactivate":      func(c context.Context, v *Vehicle) error { return v.DeactivateSpeedLimit(c, "1111") },
	"speed_limit_set_limit_65":    func(c context.Context, v *Vehicle) error { return v.SpeedLimitSetLimitMPH(c, 65) },
	"speed_limit_clear_pin":       func(c context.Context, v *Vehicle) error { return v.ClearSpeedLimitPIN(c, "1111") },
	"speed_limit_clear_pin_admin": func(c context.Context, v *Vehicle) error { return v.ClearSpeedLimitPINAdminAction(c) },
	"guest_mode_on":               func(c context.Context, v *Vehicle) error { return v.SetGuestMode(c, true) },
	"guest_mode_off":              func(c context.Context, v *Vehicle) error { return v.SetGuestMode(c, false) },
	"erase_user_data":             func(c context.Context, v *Vehicle) error { return v.EraseGuestData(c) },
	"trigger_homelink":            func(c context.Context, v *Vehicle) error { return v.TriggerHomelink(c, 37.5, -122.25) },

	"schedule_software_update_2h": func(c context.Context, v *Vehicle) error {
		return v.ScheduleSoftwareUpdate(c, 2*time.Hour)
	},
	"cancel_software_update": func(c context.Context, v *Vehicle) error { return v.CancelSoftwareUpdate(c) },
	"set_vehicle_name":       func(c context.Context, v *Vehicle) error { return v.SetVehicleName(c, "Road Runner") },
	"ping":                   func(c context.Context, v *Vehicle) error { return v.Ping(c) },
}

type commandVector struct {
	ID      string `json:"id"`
	Command string `json:"command"`
	Domain  int32  `json:"domain"`
	Payload string `json:"payload"`
}

func loadCommandVectors(t *testing.T) []commandVector {
	t.Helper()
	path := os.Getenv("TESLA_MCP_COMMAND_VECTORS")
	if path == "" {
		t.Fatal("TESLA_MCP_COMMAND_VECTORS must point at test/vectors/vcp-commands.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []commandVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no command vectors")
	}
	return file.Vectors
}

// teslaPayload runs one Tesla call and returns the domain and payload it sent.
func teslaPayload(t *testing.T, call func(context.Context, *Vehicle) error) (universal.Domain, []byte) {
	t.Helper()
	sender := &captureSender{}
	v := &Vehicle{
		Flags:        DefaultFlags,
		dispatcher:   sender,
		vin:          "5YJ3E1EA1NF000001",
		conn:         fleetConnector{},
		authMethod:   connector.AuthMethodHMAC,
		keyAvailable: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := call(ctx, v); !errors.Is(err, errCaptured) {
		t.Fatalf("Tesla's call did not reach the dispatcher: %v", err)
	}
	if sender.message == nil {
		t.Fatal("no message captured")
	}
	return sender.message.GetToDestination().GetDomain(), sender.message.GetProtobufMessageAsBytes()
}

// equalPayload decodes both payloads with Tesla's schema for the domain and
// requires proto.Equal (unknown fields included).
func equalPayload(domain universal.Domain, a, b []byte) error {
	var left, right proto.Message
	switch domain {
	case universal.Domain_DOMAIN_VEHICLE_SECURITY:
		left, right = &vcsec.UnsignedMessage{}, &vcsec.UnsignedMessage{}
	case universal.Domain_DOMAIN_INFOTAINMENT:
		left, right = &carserver.Action{}, &carserver.Action{}
	default:
		return fmt.Errorf("unexpected domain %d", domain)
	}
	if err := proto.Unmarshal(a, left); err != nil {
		return err
	}
	if err := proto.Unmarshal(b, right); err != nil {
		return err
	}
	if !proto.Equal(left, right) {
		return errors.New("decoded messages differ")
	}
	return nil
}

func TestTeslaMCPCommandConformance(t *testing.T) {
	vectors := loadCommandVectors(t)
	seen := map[string]bool{}
	for _, vector := range vectors {
		vector := vector
		if seen[vector.ID] {
			t.Fatalf("duplicate vector id %q", vector.ID)
		}
		seen[vector.ID] = true
		t.Run(vector.ID, func(t *testing.T) {
			want, err := hex.DecodeString(vector.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var domain universal.Domain
			var got []byte
			if action, ok := schemaCommands[vector.ID]; ok {
				domain = universal.Domain_DOMAIN_INFOTAINMENT
				if got, err = proto.Marshal(action); err != nil {
					t.Fatal(err)
				}
			} else if call, ok := teslaCalls[vector.ID]; ok {
				domain, got = teslaPayload(t, call)
			} else {
				t.Fatalf("no Tesla call for vector %q", vector.ID)
			}
			// One line per mismatch that can be pasted back into the vectors.
			report := fmt.Sprintf("TESLA_VECTOR {\"id\":%q,\"domain\":%d,\"payload\":%q}", vector.ID, domain, hex.EncodeToString(got))
			if universal.Domain(vector.Domain) != domain {
				t.Errorf("domain %d, Tesla sends %d\n%s", vector.Domain, domain, report)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("payload mismatch\n  tesla:   %x\n  vectors: %x\n%s", got, want, report)
			} else if err := equalPayload(domain, got, want); err != nil {
				t.Error(err)
			}
		})
	}
	var missing []string
	for id := range teslaCalls {
		if !seen[id] {
			missing = append(missing, id)
		}
	}
	for id := range schemaCommands {
		if !seen[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("Tesla calls without a vector: %v", missing)
	}
}
