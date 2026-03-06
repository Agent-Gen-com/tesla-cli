//! Protobuf payload builders for each supported command.
//! Field numbers match Tesla's vehicle-command proto definitions.

use super::proto::{encode_bytes_field, encode_tag, encode_varint_field};

pub const DOMAIN_VCSEC: u8 = 2;
pub const DOMAIN_INFOTAINMENT: u8 = 3;

// ---------------------------------------------------------------------------
// VCSEC (UnsignedMessage field 2 = RKEAction_E enum)
// ---------------------------------------------------------------------------

fn vcsec_rke(action: u64) -> Vec<u8> {
    encode_varint_field(2, action)
}

// ---------------------------------------------------------------------------
// Infotainment helpers
// ---------------------------------------------------------------------------

/// Wrap an inner action in `VehicleAction { field_number: inner } → Action { vehicleAction(2): ... }`.
fn wrap_vehicle_action(field_number: u32, inner: &[u8]) -> Vec<u8> {
    let vehicle_action = encode_bytes_field(field_number, inner);
    encode_bytes_field(2, &vehicle_action)
}

fn void_vehicle_action(field_number: u32) -> Vec<u8> {
    wrap_vehicle_action(field_number, &[])
}

fn encode_float_field(field_number: u32, value: f32) -> Vec<u8> {
    let mut out = encode_tag(field_number, 5);
    out.extend_from_slice(&value.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// Command enum
// ---------------------------------------------------------------------------

/// All supported VCP commands.
#[derive(Debug, Clone)]
pub enum Command {
    // VCSEC
    Lock,
    Unlock,
    // Infotainment — void
    Flash,
    Honk,
    ClimateStart,
    ClimateStop,
    ChargeStart,
    ChargeStop,
    // Infotainment — with params
    ClimateSetTemp { temp_c: f32 },
    ChargeSetLimit { percent: u32 },
    ChargeSetAmps { amps: u32 },
}

impl Command {
    pub fn domain(&self) -> u8 {
        match self {
            Command::Lock | Command::Unlock => DOMAIN_VCSEC,
            _ => DOMAIN_INFOTAINMENT,
        }
    }

    /// Build the serialized protobuf payload for `protobuf_message_as_bytes`.
    pub fn build_payload(&self) -> Vec<u8> {
        match self {
            // VCSEC RKE actions
            Command::Lock => vcsec_rke(1),   // RKE_LOCK = 1
            Command::Unlock => vcsec_rke(0), // RKE_UNLOCK = 0

            // Infotainment — void VehicleActions
            Command::Flash => void_vehicle_action(26), // _VA_FLASH_LIGHTS = 26
            Command::Honk => void_vehicle_action(27),  // _VA_HONK_HORN = 27

            // HVAC auto (field 10 = _VA_HVAC_AUTO)
            Command::ClimateStart => {
                let inner = encode_varint_field(1, 1); // power_on = true
                wrap_vehicle_action(10, &inner)
            }
            Command::ClimateStop => {
                let inner = encode_varint_field(1, 0); // power_on = false
                wrap_vehicle_action(10, &inner)
            }

            // HVAC temperature adjustment (field 14 = _VA_HVAC_TEMP_ADJUSTMENT)
            // driver_temp = field 6 (float), passenger_temp = field 7 (float)
            Command::ClimateSetTemp { temp_c } => {
                let mut inner = Vec::new();
                inner.extend(encode_float_field(6, *temp_c)); // driver_temp
                inner.extend(encode_float_field(7, *temp_c)); // passenger_temp
                wrap_vehicle_action(14, &inner)
            }

            // Charging start/stop (field 6 = _VA_CHARGING_START_STOP)
            Command::ChargeStart => {
                let inner = encode_bytes_field(2, &[]); // start = field 2: Void
                wrap_vehicle_action(6, &inner)
            }
            Command::ChargeStop => {
                let inner = encode_bytes_field(5, &[]); // stop = field 5: Void
                wrap_vehicle_action(6, &inner)
            }

            // Charging set limit (field 5 = _VA_CHARGING_SET_LIMIT)
            // ChargingSetLimitAction { percent (field 1) }
            Command::ChargeSetLimit { percent } => {
                let inner = encode_varint_field(1, *percent as u64);
                wrap_vehicle_action(5, &inner)
            }

            // Set charging amps (field 43 = _VA_SET_CHARGING_AMPS)
            // SetChargingAmpsAction { charging_amps (field 1) }
            Command::ChargeSetAmps { amps } => {
                let inner = encode_varint_field(1, *amps as u64);
                wrap_vehicle_action(43, &inner)
            }
        }
    }
}
