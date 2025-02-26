use aes_gcm::{Aes128Gcm, Key, KeyInit};
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use sha2::Sha256;

pub struct E2EAuth<'a> {
    ecdh: EphemeralSecret,
    auth: &'a str,
}

pub struct E2ESecret<'a> {
    auth: &'a str,
    context: Vec<u8>,
    secret: [u8; 32],
}

impl<'a> E2ESecret<'a> {
    fn build_info(&self, prefix: &[u8]) -> Vec<u8> {
        let mut info = prefix.to_vec();
        info.extend_from_slice(self.context.as_slice());
        info
    }

    fn aes_key(&self) -> Key<Aes128Gcm> {
        let mut key = Key::<Aes128Gcm>::default();
        let mut hkdf =
            Hkdf::<Sha256>::new(Some(self.auth.as_bytes()), b"Content-Encoding: aesgcm\0");
        hkdf.expand(&self.build_info(b"Content-Encoding: aesgcm\0"), &mut key)
            .expect("hkdf expand");

        key
    }

    pub fn chunk_encrypt(&self, chunk_id: u32) -> Aes128Gcm {
        let mut nonce = [0u8; 12];
        let hkdf = Hkdf::<Sha256>::new(Some(self.auth.as_bytes()), b"Content-Encoding: nonce\0");
        nonce[0..4]
            .iter_mut()
            .zip(chunk_id.to_be_bytes().iter())
            .for_each(|(a, b)| {
                *a ^= *b;
            });
        hkdf.expand(
            &self.build_info(b"Content-Encoding: nonce\0"),
            &mut nonce[4..],
        )
        .expect("hkdf expand");

        todo!();
    }
}

impl<'a> E2EAuth<'a> {
    pub fn new(ecdh: EphemeralSecret, auth: &'a str) -> Self {
        Self { ecdh, auth }
    }

    pub fn e2e_secret(&self, server_key: &p256::PublicKey) -> E2ESecret {
        let ecdh_secret = self.ecdh.diffie_hellman(server_key);
        let hkdf = Hkdf::<Sha256>::new(Some(self.auth.as_bytes()), ecdh_secret.raw_secret_bytes());
        let mut okm = [0u8; 32];
        hkdf.expand(b"Content-Encoding: auth\0", &mut okm)
            .expect("hkdf expand");
        let mut context = b"P-256\0".to_vec();
        let tmp = self.ecdh.public_key().to_sec1_bytes();
        context.extend_from_slice(&(tmp.len() as u16).to_be_bytes());
        context.extend_from_slice(&tmp);
        let tmp = server_key.to_sec1_bytes();
        context.extend_from_slice(&(tmp.len() as u16).to_be_bytes());
        context.extend_from_slice(&tmp);
        E2ESecret {
            auth: self.auth,
            context,
            secret: okm,
        }
    }
}
