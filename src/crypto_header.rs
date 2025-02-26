use core::error;
use std::borrow::Cow;

use axum::{
    extract::FromRequestParts,
    response::{IntoResponse, Response},
};
use axum_extra::headers::{Header, authorization::Credentials};
use base64::{
    Engine,
    prelude::{BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD},
};
use http::{HeaderName, HeaderValue, StatusCode, header, request::Parts};
use jwt::{RegisteredClaims, Token, VerifyWithKey, VerifyingAlgorithm};
use p256::ecdsa::{self, signature::DigestVerifier};
use sha2::{Digest, Sha256};
use tracing::{debug, error, warn};

#[derive(Debug, thiserror::Error)]
pub enum VapidError {
    #[error("Invalid format")]
    InvalidFormat(#[from] nom::Err<nom::error::Error<String>>),

    #[error("Trailing VAPID header")]
    TrailingVapidHeader,

    #[error("Invalid key")]
    InvalidKey(#[from] p256::ecdsa::Error),

    #[error("Invalid authorization header")]
    InvalidAuthorizationHeader,
    #[error("Missing VAPID ECDH key")]
    MissingECDHKey,
    #[error("Missing JWT")]
    MissingJwt,

    #[error("Bad JWT: {0}")]
    Jwt(#[from] jwt::error::Error),

    #[error("Bad base64: {0}")]
    Base64(#[from] base64::DecodeError),
}

impl IntoResponse for VapidError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoKeyError {
    #[error("Invalid format")]
    InvalidFormat(#[from] nom::Err<nom::error::Error<String>>),

    #[error("Unknown key id: {0}")]
    UnknownKeyId(String),
}

#[derive(Debug)]
pub struct CryptoKey {
    ecdsa: p256::ecdsa::VerifyingKey,
    dh: Option<p256::PublicKey>,
}

impl Header for CryptoKey {
    fn name() -> &'static HeaderName {
        static CRYPTO_KEY_HEADER: HeaderName = HeaderName::from_static("crypto-key");
        &CRYPTO_KEY_HEADER
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, axum_extra::headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let first = values.next().ok_or(axum_extra::headers::Error::invalid())?;
        if values.next().is_some() {
            return Err(axum_extra::headers::Error::invalid());
        }
        let first = first
            .to_str()
            .map_err(|_| axum_extra::headers::Error::invalid())?;

        let map = parser::header_map(first, ";", false)
            .map_err(|e| {
                error!("Error decoding crypto-key: {:?}", e);
                axum_extra::headers::Error::invalid()
            })?
            .1;

        let ecdsa = map
            .get("keyidp256ecdsa")
            .ok_or(axum_extra::headers::Error::invalid())?;
        let ecdsa = p256::ecdsa::VerifyingKey::from_sec1_bytes(
            &BASE64_URL_SAFE_NO_PAD.decode(ecdsa).map_err(|e| {
                error!("Error decoding P256ECDSA key (not base64): {:?}", e);
                axum_extra::headers::Error::invalid()
            })?,
        )
        .map_err(|e| {
            error!("Error decoding P256ECDSA key: {:?}", e);
            axum_extra::headers::Error::invalid()
        })?;

        let dh = map
            .get("dh")
            .map(|dh_hdr| {
                let dh_pub = BASE64_URL_SAFE_NO_PAD.decode(dh_hdr).map_err(|e| {
                    error!("Error decoding P256DH ephemeral key (not base64): {:?}", e);
                    axum_extra::headers::Error::invalid()
                })?;
                p256::PublicKey::from_sec1_bytes(&dh_pub).map_err(|e| {
                    error!("Error decoding P256DH ephemeral key: {:?}", e);
                    axum_extra::headers::Error::invalid()
                })
            })
            .transpose()
            .map_err(|e| {
                error!("Error decoding P256DH ephemeral key: {:?}", e);
                axum_extra::headers::Error::invalid()
            })?;

        Ok(CryptoKey { ecdsa, dh })
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        unimplemented!()
    }
}

#[derive(Debug)]
pub enum EncryptionSalt {
    P256([u8; 16]),
}

impl Header for EncryptionSalt {
    fn name() -> &'static HeaderName {
        static ENCRYPTION_HEADER: HeaderName = HeaderName::from_static("encryption");
        &ENCRYPTION_HEADER
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, axum_extra::headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let first = values.next().ok_or(axum_extra::headers::Error::invalid())?;
        if values.next().is_some() {
            return Err(axum_extra::headers::Error::invalid());
        }
        let first = first
            .to_str()
            .map_err(|_| axum_extra::headers::Error::invalid())?;
        let map = parser::header_map(first, ";", false)
            .map_err(|e| {
                error!("Error decoding encryption salt: {:?}", e);
                axum_extra::headers::Error::invalid()
            })?
            .1;

        match map.get("keyid") {
            Some(&"p256dh") | None => {
                let salt = map
                    .get("salt")
                    .ok_or(axum_extra::headers::Error::invalid())?;
                let mut salt_out = [0u8; 16];
                BASE64_URL_SAFE_NO_PAD
                    .decode_slice(salt, &mut salt_out)
                    .map_err(|e| {
                        error!("Error decoding encryption salt: {:?}", e);
                        axum_extra::headers::Error::invalid()
                    })?;
                Ok(EncryptionSalt::P256(salt_out))
            }
            Some(key_id) => {
                error!("Unknown key id: {}", key_id);
                Err(axum_extra::headers::Error::invalid())
            }
        }
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct Vapid {
    claims: RegisteredClaims,
    vapid_pub: p256::ecdsa::VerifyingKey,
}

pub struct Es256Verifier(p256::ecdsa::VerifyingKey);

impl VerifyingAlgorithm for Es256Verifier {
    fn algorithm_type(&self) -> jwt::AlgorithmType {
        jwt::AlgorithmType::Es256
    }

    fn verify_bytes(
        &self,
        header: &str,
        claims: &str,
        signature: &[u8],
    ) -> Result<bool, jwt::error::Error> {
        let mut sha256 = Sha256::new();
        sha256.update(header.as_bytes());
        sha256.update(b".");
        sha256.update(claims.as_bytes());
        let signature = ecdsa::Signature::from_bytes(signature.into()).map_err(|e| {
            error!("Cannot parse signature: {:?}", e);
            jwt::error::Error::InvalidSignature
        })?;
        debug!("Verifying signature: {:?}", signature);
        Ok(self.0.verify_digest(sha256, &signature).is_ok())
    }
}

impl Credentials for Vapid {
    const SCHEME: &'static str = "vapid";

    fn decode(value: &HeaderValue) -> Option<Self> {
        let value = parser::strip_prefix(value.to_str().ok()?)?;

        let vapid = Vapid::from_authorization_value(value.trim()).ok()?;
        Some(vapid)
    }

    fn encode(&self) -> HeaderValue {
        unimplemented!()
    }
}

impl Vapid {
    fn from_authorization_value<'a>(auth_value: &'a str) -> Result<Self, VapidError> {
        debug!("Detected VAPID header: {}", auth_value);
        let (rest, header_map) = parser::header_map(auth_value, ",", true)
            .map_err(|e| e.map_input(|s| s.to_string()))
            .map_err(VapidError::InvalidFormat)?;

        if !rest.is_empty() {
            return Err(VapidError::TrailingVapidHeader);
        }

        let jwt = header_map
            .get("t")
            .map(|s| *s)
            .ok_or(VapidError::MissingJwt)?;

        let ec_key = header_map
            .get("k")
            .map(|s| *s)
            .ok_or(VapidError::MissingECDHKey)?;

        let p256_pub =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&BASE64_URL_SAFE_NO_PAD.decode(ec_key)?)
                .map_err(VapidError::InvalidKey)?;

        let claims: RegisteredClaims = jwt.verify_with_key(&Es256Verifier(p256_pub))?;

        Ok(Self {
            claims,
            vapid_pub: p256_pub,
        })
    }
}

mod parser {
    use std::{collections::HashMap, convert::Infallible};

    use nom::{
        IResult, Parser,
        bytes::complete::{tag, take_while1},
        character::complete::{alpha1, space0, space1},
        combinator::eof,
        multi::separated_list1,
        sequence::{delimited, separated_pair, terminated, tuple},
    };

    use super::VapidError;

    pub fn strip_prefix(authorization: &str) -> Option<&str> {
        let (prefix, key) = authorization.split_once(" ")?;
        if !prefix.eq_ignore_ascii_case("vapid") {
            return None;
        }
        Some(key)
    }

    pub fn key_val(input: &str) -> IResult<&str, (&str, &str)> {
        separated_pair(
            alpha1,
            tag("="),
            take_while1(|s: char| s.is_ascii_alphanumeric() || s == '-' || s == '_' || s == '.'),
        )
        .parse(input)
    }

    pub fn header_map<'a>(
        input: &'a str,
        sep: &'static str,
        require_space: bool,
    ) -> IResult<&'a str, HashMap<&'a str, &'a str>> {
        terminated(
            separated_list1(
                (tag(sep), if require_space { space1 } else { space0 }),
                key_val,
            ),
            eof,
        )
        .map_res(|o| Ok::<_, Infallible>(o.into_iter().collect()))
        .parse_complete(input)
    }

    mod tests {
        use crate::crypto_header::parser::header_map;

        #[test]
        fn test_header_map() {
            let input = "t=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3RzdWJhc2EtcHJveHkueXVtZS1jb2xsYWIub3JnIiwiZXhwIjoxNzQwNTg4NzI1LCJzdWIiOiJtYWlsdG86c2ltcGxlLXB1c2gtZGVtb0BnYXVudGZhY2UuY28udWsifQ.nTpdTYF2GLvN29z169LiXtKdkDU65GYVsSTprhBhNtONvquDrAFbjdWuBfEI7Hj4gCptqu3hbsDMINV4yDo_uA, k=BDd3_hVL9fZi9Ybo2UUzA284WG5FZR30_95YeZJsiApwXKpNcF1rRPF3foIiBHXRdJI2Qhumhf6_LFTeZaNndIo";
            let (rest, header_map) = header_map(input, ",", true).unwrap();
            assert!(rest.is_empty());
            assert_eq!(header_map.len(), 2);
            assert_eq!(
                header_map.get("t"),
                Some(
                    &"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3RzdWJhc2EtcHJveHkueXVtZS1jb2xsYWIub3JnIiwiZXhwIjoxNzQwNTg4NzI1LCJzdWIiOiJtYWlsdG86c2ltcGxlLXB1c2gtZGVtb0BnYXVudGZhY2UuY28udWsifQ.nTpdTYF2GLvN29z169LiXtKdkDU65GYVsSTprhBhNtONvquDrAFbjdWuBfEI7Hj4gCptqu3hbsDMINV4yDo_uA"
                )
            );
            assert_eq!(
                header_map.get("k"),
                Some(
                    &"BDd3_hVL9fZi9Ybo2UUzA284WG5FZR30_95YeZJsiApwXKpNcF1rRPF3foIiBHXRdJI2Qhumhf6_LFTeZaNndIo"
                )
            );
        }
    }
}
