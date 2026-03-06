//! Minimal hand-written protobuf wire-format helpers.
//! No generated code, no .proto files — matches the Python implementation.

/// Encode a varint (base-128).
pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        if value <= 0x7F {
            result.push(value as u8);
            break;
        }
        result.push(((value & 0x7F) | 0x80) as u8);
        value >>= 7;
    }
    result
}

/// Encode a protobuf field tag: (field_number << 3) | wire_type.
pub fn encode_tag(field_number: u32, wire_type: u8) -> Vec<u8> {
    encode_varint(((field_number as u64) << 3) | wire_type as u64)
}

/// Encode a varint field (wire type 0).
pub fn encode_varint_field(field_number: u32, value: u64) -> Vec<u8> {
    let mut out = encode_tag(field_number, 0);
    out.extend(encode_varint(value));
    out
}

/// Encode a length-delimited field (wire type 2): tag || varint(len) || data.
pub fn encode_bytes_field(field_number: u32, data: &[u8]) -> Vec<u8> {
    let mut out = encode_tag(field_number, 2);
    out.extend(encode_varint(data.len() as u64));
    out.extend_from_slice(data);
    out
}

/// Encode a fixed32 field (wire type 5, little-endian).
pub fn encode_fixed32_field(field_number: u32, value: u32) -> Vec<u8> {
    let mut out = encode_tag(field_number, 5);
    out.extend_from_slice(&value.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub enum FieldValue {
    Varint(u64),
    Bytes(Vec<u8>),
    Fixed32(u32),
    Fixed64(u64),
}

/// Decode a varint from `data` starting at `pos`.
/// Returns `(value, new_pos)`.
pub fn decode_varint(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut p = pos;
    while p < data.len() {
        let b = data[p];
        result |= ((b & 0x7F) as u64) << shift;
        p += 1;
        if b & 0x80 == 0 {
            return Some((result, p));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

/// Decode one protobuf field at `pos`.
/// Returns `(field_number, value, new_pos)` or `None` on error.
pub fn decode_field(data: &[u8], pos: usize) -> Option<(u32, FieldValue, usize)> {
    let (tag, pos) = decode_varint(data, pos)?;
    let field_number = (tag >> 3) as u32;
    let wire_type = (tag & 0x07) as u8;
    match wire_type {
        0 => {
            let (val, new_pos) = decode_varint(data, pos)?;
            Some((field_number, FieldValue::Varint(val), new_pos))
        }
        2 => {
            let (len, pos2) = decode_varint(data, pos)?;
            let len = len as usize;
            let new_pos = pos2 + len;
            if new_pos > data.len() {
                return None;
            }
            Some((field_number, FieldValue::Bytes(data[pos2..new_pos].to_vec()), new_pos))
        }
        5 => {
            if pos + 4 > data.len() {
                return None;
            }
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&data[pos..pos + 4]);
            Some((field_number, FieldValue::Fixed32(u32::from_le_bytes(bytes)), pos + 4))
        }
        1 => {
            // 64-bit fixed
            if pos + 8 > data.len() {
                return None;
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[pos..pos + 8]);
            Some((field_number, FieldValue::Fixed64(u64::from_le_bytes(bytes)), pos + 8))
        }
        _ => None,
    }
}
