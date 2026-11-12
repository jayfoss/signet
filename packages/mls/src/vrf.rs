//! ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 §5, suite 0x03).
//!
//! Signet indexes the transparency log by VRF output instead of a plain hash of the address. Only the
//! domain, which holds the VRF key, can compute an address's index, and it proves the index on every
//! lookup. Nobody can test guessed addresses against the log offline.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha512};

const SUITE: u8 = 0x03;
const C_LEN: usize = 16;
pub const PROOF_LEN: usize = 80;

pub type Result<T> = std::result::Result<T, String>;

pub struct VrfKey {
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

fn expand(secret: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let h = Sha512::digest(secret);
    let mut lower = [0u8; 32];
    lower.copy_from_slice(&h[..32]);
    lower[0] &= 248;
    lower[31] &= 127;
    lower[31] |= 64;
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h[32..]);
    // The clamped value exceeds the group order, but only its value mod the order matters for
    // multiples of points in the prime-order subgroup.
    (Scalar::from_bytes_mod_order(lower), prefix)
}

pub fn keygen() -> VrfKey {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    from_secret(secret)
}

pub fn from_secret(secret: [u8; 32]) -> VrfKey {
    let (x, _) = expand(&secret);
    VrfKey { secret, public: EdwardsPoint::mul_base(&x).compress().to_bytes() }
}

/// RFC 9381 §5.4.1.1 encode_to_curve, try-and-increment.
fn encode_to_curve(public: &[u8; 32], alpha: &[u8]) -> Result<EdwardsPoint> {
    for counter in 0u8..=255 {
        let mut hash = Sha512::new();
        hash.update([SUITE, 0x01]);
        hash.update(public);
        hash.update(alpha);
        hash.update([counter, 0x00]);
        let digest = hash.finalize();
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&digest[..32]);
        if let Some(point) = CompressedEdwardsY(candidate).decompress() {
            return Ok(point.mul_by_cofactor());
        }
    }
    Err("encode_to_curve found no point".into())
}

/// RFC 9381 §5.4.3 challenge generation.
fn challenge(points: [&EdwardsPoint; 5]) -> Scalar {
    let mut hash = Sha512::new();
    hash.update([SUITE, 0x02]);
    for point in points {
        hash.update(point.compress().as_bytes());
    }
    hash.update([0x00]);
    let digest = hash.finalize();
    let mut c = [0u8; 32];
    c[..C_LEN].copy_from_slice(&digest[..C_LEN]);
    Scalar::from_bytes_mod_order(c)
}

fn proof_to_hash(gamma: &EdwardsPoint) -> [u8; 64] {
    let mut hash = Sha512::new();
    hash.update([SUITE, 0x03]);
    hash.update(gamma.mul_by_cofactor().compress().as_bytes());
    hash.update([0x00]);
    hash.finalize().into()
}

/// Prove `alpha` under the secret key. Returns (proof, output).
pub fn prove(secret: &[u8; 32], alpha: &[u8]) -> Result<([u8; PROOF_LEN], [u8; 64])> {
    let (x, prefix) = expand(secret);
    let public = EdwardsPoint::mul_base(&x).compress().to_bytes();
    let h = encode_to_curve(&public, alpha)?;
    let gamma = h * x;
    // RFC 9381 §5.4.2.2: nonce as in RFC 8032.
    let mut nonce = Sha512::new();
    nonce.update(prefix);
    nonce.update(h.compress().as_bytes());
    let k = Scalar::from_bytes_mod_order_wide(&nonce.finalize().into());
    let y = CompressedEdwardsY(public).decompress().ok_or("bad public key")?;
    let c = challenge([&y, &h, &gamma, &EdwardsPoint::mul_base(&k), &(h * k)]);
    let s = k + c * x;
    let mut proof = [0u8; PROOF_LEN];
    proof[..32].copy_from_slice(gamma.compress().as_bytes());
    proof[32..48].copy_from_slice(&c.to_bytes()[..C_LEN]);
    proof[48..].copy_from_slice(s.as_bytes());
    Ok((proof, proof_to_hash(&gamma)))
}

/// Verify a proof for `alpha` under the public key and return the VRF output.
pub fn verify(public: &[u8; 32], alpha: &[u8], proof: &[u8]) -> Result<[u8; 64]> {
    if proof.len() != PROOF_LEN {
        return Err("proof has the wrong length".into());
    }
    let y = CompressedEdwardsY(*public).decompress().ok_or("public key is not a point")?;
    if y.is_small_order() {
        return Err("public key has small order".into());
    }
    let gamma = CompressedEdwardsY(proof[..32].try_into().unwrap()).decompress().ok_or("proof is not a point")?;
    let mut c_bytes = [0u8; 32];
    c_bytes[..C_LEN].copy_from_slice(&proof[32..48]);
    let c = Scalar::from_bytes_mod_order(c_bytes);
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(proof[48..].try_into().unwrap())).ok_or("proof scalar is not canonical")?;
    let h = encode_to_curve(public, alpha)?;
    let u = EdwardsPoint::mul_base(&s) - y * c;
    let v = h * s - gamma * c;
    if challenge([&y, &h, &gamma, &u, &v]) != c {
        return Err("VRF proof is invalid".into());
    }
    Ok(proof_to_hash(&gamma))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// RFC 9381 Appendix B.3, Example 16 (empty alpha).
    #[test]
    fn matches_rfc_9381_vector() {
        let secret: [u8; 32] = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").try_into().unwrap();
        let key = from_secret(secret);
        assert_eq!(key.public.to_vec(), hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
        let (proof, output) = prove(&secret, b"").unwrap();
        assert_eq!(
            proof.to_vec(),
            hex("8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805")
        );
        assert_eq!(
            output.to_vec(),
            hex("90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae")
        );
        assert_eq!(verify(&key.public, b"", &proof).unwrap(), output);
    }

    #[test]
    fn rejects_wrong_input_key_or_proof() {
        let key = keygen();
        let (proof, _) = prove(&key.secret, b"alice@example.org").unwrap();
        assert!(verify(&key.public, b"bob@example.org", &proof).is_err());
        assert!(verify(&keygen().public, b"alice@example.org", &proof).is_err());
        let mut bad = proof;
        bad[40] ^= 1;
        assert!(verify(&key.public, b"alice@example.org", &bad).is_err());
    }
}
