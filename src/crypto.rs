use anyhow::{Context, Result};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use p256::{SecretKey};

/// Generate a new P-256 key pair, saving PKCS#8 private key + SPKI public key PEMs.
/// Returns `(private_pem, public_pem)`.
pub fn generate_key_pair() -> Result<(String, String)> {
    let secret = SecretKey::random(&mut rand::rngs::OsRng);

    let private_pem = secret
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("PKCS8 encode error: {}", e))?;
    let private_pem_str = private_pem.as_str().to_string();

    let public_pem = secret
        .public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("SPKI PEM encode error: {}", e))?;

    Ok((private_pem_str, public_pem))
}

/// Load a P-256 private key from a PKCS#8 PEM file.
pub fn load_private_key(pem: &str) -> Result<SecretKey> {
    SecretKey::from_pkcs8_pem(pem).map_err(|e| anyhow::anyhow!("Invalid private key PEM: {}", e))
}

/// Return the uncompressed 65-byte public key point (0x04 || X || Y).
pub fn uncompressed_public_key(secret: &SecretKey) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    secret.public_key().to_encoded_point(false).as_bytes().to_vec()
}

/// ECDH key derivation: SHA1(shared_secret)[:16]
///
/// Tesla's VCP spec requires SHA-1 for the session key KDF (not SHA-256).
pub fn derive_session_key(secret: &SecretKey, vehicle_pub_bytes: &[u8]) -> Result<[u8; 16]> {
    use p256::{PublicKey};
    use p256::elliptic_curve::sec1::FromEncodedPoint;

    let encoded_point = p256::EncodedPoint::from_bytes(vehicle_pub_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid vehicle public key bytes: {:?}", e))?;
    let vehicle_pub = PublicKey::from_encoded_point(&encoded_point)
        .into_option()
        .context("Invalid vehicle public key point")?;

    let shared = p256::elliptic_curve::ecdh::diffie_hellman(
        secret.to_nonzero_scalar(),
        vehicle_pub.as_affine(),
    );
    let raw = shared.raw_secret_bytes();

    use sha1::Digest;
    let hash = sha1::Sha1::digest(&raw[..]);
    let mut session_key = [0u8; 16];
    session_key.copy_from_slice(&hash[..16]);
    Ok(session_key)
}
