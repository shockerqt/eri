use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub const CLOCK_SKEW_SECONDS: u64 = 30;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    active: ActiveKey,
    #[serde(default)]
    previous: Vec<PublicKey>,
    #[serde(default)]
    next: Vec<PublicKey>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveKey {
    kid: String,
    private_key: PathBuf,
    public_key: PathBuf,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKey {
    kid: String,
    public_key: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct Jwk {
    pub kty: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
    pub kid: String,
    pub n: String,
    pub e: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

pub struct SigningKeys {
    active_kid: String,
    encoding: EncodingKey,
    decoding: HashMap<String, DecodingKey>,
    jwks_json: String,
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("cannot read key configuration: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid key manifest: {0}")]
    Manifest(#[from] serde_json::Error),
    #[error("invalid signing keys: {0}")]
    Invalid(String),
    #[error("token operation failed: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

impl SigningKeys {
    pub fn load(manifest_path: &Path) -> Result<Self, KeyError> {
        let manifest: Manifest = serde_json::from_str(&fs::read_to_string(manifest_path)?)?;
        let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));
        check_kid(&manifest.active.kid)?;
        let private_path = base.join(&manifest.active.private_key);
        let private_pem = read_private_key(&private_path)?;
        let private = parse_private(&private_pem)?;
        validate_size(private.n().bits())?;
        let active_public_pem = fs::read(base.join(&manifest.active.public_key))?;
        let active_public = parse_public(&active_public_pem)?;
        if private.to_public_key() != active_public {
            return Err(invalid("active private and public keys do not match"));
        }

        let mut seen = HashSet::new();
        let mut seen_material = HashSet::new();
        let mut decoding = HashMap::new();
        let mut jwks = Vec::new();
        add_public(
            &manifest.active.kid,
            active_public,
            &active_public_pem,
            &mut seen,
            &mut seen_material,
            &mut decoding,
            &mut jwks,
        )?;
        for entry in manifest.previous.iter().chain(manifest.next.iter()) {
            check_kid(&entry.kid)?;
            let pem = fs::read(base.join(&entry.public_key))?;
            add_public(
                &entry.kid,
                parse_public(&pem)?,
                &pem,
                &mut seen,
                &mut seen_material,
                &mut decoding,
                &mut jwks,
            )?;
        }
        let encoding = EncodingKey::from_rsa_pem(&private_pem)?;
        let jwks_json =
            serde_json::to_string(&JwkSet { keys: jwks }).map_err(KeyError::Manifest)?;
        Ok(Self {
            active_kid: manifest.active.kid,
            encoding,
            decoding,
            jwks_json,
        })
    }

    pub fn jwks_json(&self) -> &str {
        &self.jwks_json
    }
    pub fn active_kid(&self) -> &str {
        &self.active_kid
    }

    pub fn sign<T: Serialize>(&self, claims: &T) -> Result<String, KeyError> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());
        header.typ = Some("at+jwt".into());
        Ok(jsonwebtoken::encode(&header, claims, &self.encoding)?)
    }

    pub fn verify<T: DeserializeOwned>(
        &self,
        token: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<T, KeyError> {
        let header = jsonwebtoken::decode_header(token)?;
        if header.alg != Algorithm::RS256 || header.typ.as_deref() != Some("at+jwt") {
            return Err(invalid("token algorithm or type is invalid"));
        }
        let kid = header.kid.ok_or_else(|| invalid("token kid is missing"))?;
        let key = self
            .decoding
            .get(&kid)
            .ok_or_else(|| invalid("token kid is unknown"))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.leeway = CLOCK_SKEW_SECONDS;
        Ok(jsonwebtoken::decode::<T>(token, key, &validation)?.claims)
    }
}

fn add_public(
    kid: &str,
    key: RsaPublicKey,
    pem: &[u8],
    seen: &mut HashSet<String>,
    seen_material: &mut HashSet<(Vec<u8>, Vec<u8>)>,
    decoding: &mut HashMap<String, DecodingKey>,
    jwks: &mut Vec<Jwk>,
) -> Result<(), KeyError> {
    if !seen.insert(kid.to_owned()) {
        return Err(invalid("duplicate kid"));
    }
    validate_size(key.n().bits())?;
    if !seen_material.insert((key.n().to_bytes_be(), key.e().to_bytes_be())) {
        return Err(invalid("duplicate public key material"));
    }
    decoding.insert(kid.to_owned(), DecodingKey::from_rsa_pem(pem)?);
    jwks.push(Jwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_owned(),
        n: URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
        e: URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
    });
    Ok(())
}

fn parse_private(pem: &[u8]) -> Result<RsaPrivateKey, KeyError> {
    let text = std::str::from_utf8(pem).map_err(|_| invalid("private key is not UTF-8 PEM"))?;
    RsaPrivateKey::from_pkcs8_pem(text)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(text))
        .map_err(|_| invalid("private key is malformed"))
}
fn parse_public(pem: &[u8]) -> Result<RsaPublicKey, KeyError> {
    let text = std::str::from_utf8(pem).map_err(|_| invalid("public key is not UTF-8 PEM"))?;
    RsaPublicKey::from_public_key_pem(text)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(text))
        .map_err(|_| invalid("public key is malformed"))
}
fn validate_size(bits: usize) -> Result<(), KeyError> {
    if bits < 2048 {
        Err(invalid("RSA keys must be at least 2048 bits"))
    } else {
        Ok(())
    }
}
fn check_kid(kid: &str) -> Result<(), KeyError> {
    if kid.is_empty()
        || kid.len() > 128
        || !kid
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
    {
        Err(invalid("kid must be a stable 1-128 character identifier"))
    } else {
        Ok(())
    }
}
fn invalid(message: &str) -> KeyError {
    KeyError::Invalid(message.into())
}

fn read_private_key(path: &Path) -> Result<Vec<u8>, KeyError> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("private key must be a regular file"));
    }
    check_private_permissions(&metadata)?;
    let mut pem = Vec::new();
    file.read_to_end(&mut pem)?;
    Ok(pem)
}

#[cfg(unix)]
fn check_private_permissions(metadata: &fs::Metadata) -> Result<(), KeyError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(invalid(
            "private key permissions permit group or other access",
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
fn check_private_permissions(_metadata: &fs::Metadata) -> Result<(), KeyError> {
    Ok(())
}
