//! TLV (tag-length-value) metadata serialization for VCP command authentication.
//!
//! Format: each entry is `tag(1B) || length(1B) || value`.
//! Tags must appear in ascending order.
//!
//! Tags (from Tesla's signatures.proto):
//!   0x00 — signature_type (1 byte = 8 for HMAC_PERSONALIZED)
//!   0x01 — domain         (1 byte — numeric Domain enum: 2=VCSEC, 3=INFOTAINMENT)
//!   0x02 — personalization (VIN string bytes)
//!   0x03 — epoch           (session epoch bytes from vehicle)
//!   0x04 — expires_at      (4 bytes, BIG-endian uint32)
//!   0x05 — counter         (4 bytes, BIG-endian uint32)

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, value.len() as u8];
    out.extend_from_slice(value);
    out
}

/// Encode the full metadata block fed into the HMAC alongside the command payload.
///
/// The caller adds a bare `0xFF` separator between this metadata and the payload
/// when computing the HMAC tag.
pub fn encode_metadata(epoch: &[u8], expires_at: u32, counter: u32, domain: u8, vin: &str) -> Vec<u8> {
    let mut parts = Vec::new();
    // TAG_SIGNATURE_TYPE = 0x00 → value = 8 (HMAC_PERSONALIZED)
    parts.extend(tlv(0x00, &[8u8]));
    // TAG_DOMAIN = 0x01 → numeric domain byte
    parts.extend(tlv(0x01, &[domain]));
    // TAG_PERSONALIZATION = 0x02 → VIN bytes
    parts.extend(tlv(0x02, vin.as_bytes()));
    // TAG_EPOCH = 0x03
    parts.extend(tlv(0x03, epoch));
    // TAG_EXPIRES_AT = 0x04 → 4 bytes big-endian
    parts.extend(tlv(0x04, &expires_at.to_be_bytes()));
    // TAG_COUNTER = 0x05 → 4 bytes big-endian
    parts.extend(tlv(0x05, &counter.to_be_bytes()));
    parts
}
