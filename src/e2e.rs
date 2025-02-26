use std::io::{Cursor, Write};

use aes_gcm::aead::AeadMutInPlace;
use aes_gcm::{AeadCore, Aes128Gcm, Key, KeyInit, Nonce};
use axum::body::Bytes;
use axum::extract::FromRequest;
use futures::TryStream;
use futures::prelude::*;
use hkdf::Hkdf;
use p256::SecretKey;
use p256::ecdh::diffie_hellman;
use sha2::Sha256;

pub struct Aes128GcmP256DHBodyHeader<S: TryStream<Ok = Bytes> + Unpin> {
    salt: [u8; 16],
    record_size: u32,
    body: S,
    overrun: Bytes,
}

pub struct E2EClientAuth<'a> {
    ecdh: SecretKey,
    auth: &'a [u8],
}

impl<S: TryStream<Ok = Bytes> + Unpin> Aes128GcmP256DHBodyHeader<S> {
    pub async fn init(mut body: S) -> Result<Option<Self>, S::Error> {
        const HEADER_SIZE: usize = 16 + 4 + 1 + "p256dh".len();
        let mut header = [0u8; HEADER_SIZE];
        let mut position = 0;

        let overrun = loop {
            let chunk = body.try_next().await?;
            if let Some(chunk) = chunk {
                if chunk.len() < HEADER_SIZE - position {
                    header[position..position + chunk.len()].copy_from_slice(&chunk);
                    position += chunk.len();
                } else {
                    header[position..].copy_from_slice(&chunk[..HEADER_SIZE - position]);
                    break chunk.slice(HEADER_SIZE - position..);
                }
            } else {
                return Ok(None);
            }
        };

        let salt = header[0..16].try_into().unwrap();
        let record_size = u32::from_be_bytes(header[16..20].try_into().unwrap());

        if header[20] != "p256dh".len() as u8 {
            return Ok(None);
        }
        if &header[21..] != b"p256dh" {
            return Ok(None);
        }

        Ok(Some(Self {
            salt,
            record_size,
            body,
            overrun,
        }))
    }
}

pub struct E2ESharedSecret {
    hkdf: Hkdf<Sha256>,
}

impl E2ESharedSecret {
    pub fn new(prk: &[u8; 32], message_salt: &[u8]) -> Self {
        Self {
            hkdf: Hkdf::<Sha256>::new(Some(message_salt), prk),
        }
    }

    /// The AES encryption key.
    pub fn aes_key(&self) -> Key<Aes128Gcm> {
        let mut key = Key::<Aes128Gcm>::default();

        self.hkdf
            .expand(b"Content-Encoding: aes128gcm\0", &mut key)
            .expect("hkdf expand");

        key
    }

    /// Convenience method to get the AES cipher.
    pub fn as_cipher(&self) -> Aes128Gcm {
        Aes128Gcm::new(&self.aes_key())
    }

    /// The aes nonce for the first chunk. You need to XOR by rs using network order to get the next nonce.
    pub fn aes_nonce(&self) -> Nonce<<Aes128Gcm as AeadCore>::NonceSize> {
        let mut nonce = Nonce::default();

        self.hkdf
            .expand(b"Content-Encoding: nonce\0", &mut nonce)
            .expect("hkdf expand");

        nonce
    }
}

impl<'a> E2EClientAuth<'a> {
    pub fn new(ecdh: SecretKey, auth: &'a [u8]) -> Self {
        Self { ecdh, auth }
    }

    pub fn compute_prk(&self, server_key: &p256::PublicKey) -> [u8; 32] {
        let ecdh_secret = diffie_hellman(&self.ecdh.to_nonzero_scalar(), server_key.as_affine());
        let hkdf = Hkdf::<Sha256>::new(Some(self.auth), ecdh_secret.raw_secret_bytes());
        let mut okm = [0u8; 32];

        let mut info = b"WebPush: info\0".to_vec();
        info.extend_from_slice(&self.ecdh.public_key().to_sec1_bytes());
        info.extend_from_slice(&server_key.to_sec1_bytes());

        hkdf.expand(&info, &mut okm).expect("hkdf expand");

        okm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdh::diffie_hellman;
    use p256::{PublicKey, SecretKey};
    use sha2::digest::generic_array::GenericArray;

    #[test]
    fn test_official_vector() {
        // Input values from the test vector
        let auth_secret = "BTBZMqHH6r4Tts7J_aSIgg";
        let auth_secret_bytes = URL_SAFE_NO_PAD.decode(auth_secret).unwrap();
        let salt = "DGv6ra1nlYgDCS1FRnbzlw";
        let salt_bytes = URL_SAFE_NO_PAD.decode(salt).unwrap();
        assert_eq!(salt_bytes.len(), 16, "Salt length mismatch");

        // Server keys
        let server_private_b64 = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
        let server_private_bytes = URL_SAFE_NO_PAD.decode(server_private_b64).unwrap();
        let server_private =
            SecretKey::from_bytes(GenericArray::from_slice(&server_private_bytes)).unwrap();

        let server_public_b64 = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
        let server_public_bytes = URL_SAFE_NO_PAD.decode(server_public_b64).unwrap();
        let server_public = PublicKey::from_sec1_bytes(&server_public_bytes).unwrap();

        // Client keys
        let client_private_b64 = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
        let client_private_bytes = URL_SAFE_NO_PAD.decode(client_private_b64).unwrap();
        let client_private =
            SecretKey::from_bytes(GenericArray::from_slice(&client_private_bytes)).unwrap();
        let client_public_b64 = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
        let client_public_bytes = URL_SAFE_NO_PAD.decode(client_public_b64).unwrap();
        let client_public = PublicKey::from_sec1_bytes(&client_public_bytes).unwrap();

        let ecdh_secret_1 = diffie_hellman(
            &client_private.to_nonzero_scalar(),
            server_public.as_affine(),
        );
        let ecdh_secret_2 = diffie_hellman(
            &server_private.to_nonzero_scalar(),
            client_public.as_affine(),
        );

        assert_eq!(
            ecdh_secret_1.raw_secret_bytes(),
            ecdh_secret_2.raw_secret_bytes(),
            "ECDH did not generate the same secret"
        );

        assert_eq!(
            ecdh_secret_1.raw_secret_bytes().to_vec(),
            URL_SAFE_NO_PAD
                .decode("kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs")
                .unwrap(),
            "ECDH implementation mismatch"
        );

        let client = E2EClientAuth::new(client_private, &auth_secret_bytes);
        let prk = client.compute_prk(&server_public);

        // Create shared secret with salt
        let shared = E2ESharedSecret::new(&prk, &salt_bytes);

        // Verify CEK matches test vector
        assert_eq!(
            shared.aes_key().to_vec(),
            URL_SAFE_NO_PAD.decode("oIhVW04MRdy2XN9CiKLxTg").unwrap(),
            "Content encryption key mismatch"
        );

        // Verify nonce matches test vector
        assert_eq!(
            shared.aes_nonce().to_vec(),
            URL_SAFE_NO_PAD.decode("4h_95klXJ5E_qnoN").unwrap(),
            "Nonce mismatch"
        );
    }
}
