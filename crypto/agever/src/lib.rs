uniffi::setup_scaffolding!();

use modular_ac::{CommittedDisclosurePresenter, CommittedDisclosureVerifier, Claim, Credential, HolderKeyPair, HolderPublicKey, HolderSecretKey, Scope, Issuer, IssuerKeyPair, IssuerPublicKey, SecP256Fq, SecP256Fr, Params, Presentation, Schema, ecdsa::{self, Signature}};
use ark_ff::{BigInteger, PrimeField};

use ark_std::rand::{self, SeedableRng, rngs::StdRng};

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use sha2::{Sha256, Digest};

#[derive(Clone)]
pub struct AgeVerParams (Params);

const AGEVER_LABEL : &str = "agever";

impl AgeVerParams {
    pub fn new() -> Self {
        let schema = Schema::new(0, vec![
            (String::from("header"), 0..1),
            (String::from("name"), 1..2),
            (String::from("above16"), 2..3),
            (String::from("above18"), 3..4),
            (String::from("nbf"), 4..5),
            (String::from("exp"), 5..6),
            (String::from("holder_pk"), 6..14),
        ]);
        let params = Params::new(AGEVER_LABEL.as_bytes(), &schema);
        AgeVerParams(params)
    }
}


#[derive(uniffi::Object)]
pub struct AgeVerHolderKeyPair (HolderKeyPair);

#[uniffi::export]
impl AgeVerHolderKeyPair {
    pub fn public_key(&self) -> AgeVerHolderPublicKey {
        AgeVerHolderPublicKey(self.0.pk.clone())
    }
    pub fn secret_key(&self) -> AgeVerHolderSecretKey {
        AgeVerHolderSecretKey(self.0.sk.clone())
    }
}

#[derive(uniffi::Object, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AgeVerHolderPublicKey (pub(crate) HolderPublicKey);

#[uniffi::export]
impl AgeVerHolderPublicKey {
    pub fn to_point_string(&self) -> String {
        format!("({},{})", self.0.x, self.0.y)
    }
}

#[derive(uniffi::Object, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AgeVerHolderSecretKey (pub(crate) HolderSecretKey);

// #[derive(uniffi::Object, Clone)]
// pub struct AgeVerNonce (pub(crate) Nonce);

// #[uniffi::export]
// impl AgeVerNonce {
//     #[uniffi::constructor]
//     pub fn from_u64(n: u64) -> Self {
//         AgeVerNonce(Nonce::from(n))
//     }

//     pub fn to_bytes(&self) -> Vec<u8> {
//         let mut bytes = Vec::new();
//         self.0.serialize_compressed(&mut bytes).expect("serialization failed");
//         bytes
//     }
// }

#[derive(Clone)]
pub struct AgeVerIssuerKeyPair(IssuerKeyPair);

impl AgeVerIssuerKeyPair {
    pub fn new(rng: &mut StdRng) -> Self {
        let keypair = IssuerKeyPair::generate_using_rng_and_bbs23_params(rng, &AgeVerParams::new().0.sig_params);
        AgeVerIssuerKeyPair(keypair)
    }
}

#[derive(uniffi::Object)]
pub struct AgeVerSignature (pub(crate) Signature);

#[uniffi::export]
impl AgeVerSignature {
    pub fn as_string(&self) -> String {
        format!("({}, {})", self.0.rand_x_coord, self.0.response)
    }
}

pub struct AgeVerIssuer {
    issuer : Issuer,
    //rng : StdRng
}

impl AgeVerIssuer {
    pub fn new(params: &AgeVerParams, issuer_keypair: AgeVerIssuerKeyPair) -> Self {
        let issuer = Issuer::new(&params.0, issuer_keypair.0);
        AgeVerIssuer { issuer }
    }

    pub fn issue_credential(&self, name: String, age: u64, holder_pk: AgeVerHolderPublicKey) -> Result<AgeVerCredential, AgeVerError> {
        let mut rng = rand::rngs::StdRng::from_entropy();

        // cred is valid right away
        let nbf = chrono::Utc::now().timestamp() as u64 - 60 ; // For demo: avoid clock skew issue with holder by issuing credential with nbf in the past
        
        // and expires in 1 month:
        let exp = (chrono::Utc::now() + chrono::Duration::days(30)).timestamp() as u64;

        let cred = self.issuer.issue_credential(&mut rng, vec![
            ("header".to_string(), Claim::Value("<unused>".to_string())),
            ("name".to_string(), Claim::Value(name)),
            ("above16".to_string(), Claim::Bool(age >= 16)),
            ("above18".to_string(), Claim::Bool(age >= 18)),
            ("nbf".to_string(), Claim::Raw(nbf)),
            ("exp".to_string(), Claim::Raw(exp)),
            ("holder_pk".to_string(), Claim::HolderPk(holder_pk.0.clone())),
        ]).map_err(|e| AgeVerError::IssuanceError(e.to_string()))?;

        Ok(AgeVerCredential(cred))
    }
}

#[derive(Clone, uniffi::Object)]
pub struct AgeVerCredential (Credential);

pub struct AgeVerPresenter {
    presenter : CommittedDisclosurePresenter,
    holder_pk : AgeVerHolderPublicKey,
    //rng : StdRng
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, uniffi::Object)]
pub struct AgeVerPresentation {
    // pub above16 : bool,
    // pub above18 : bool,
    pub today : u64,
    pub presentation : Presentation,
}


#[uniffi::export]
pub fn gen_presentation(cred: &AgeVerCredential, holder_pk: &AgeVerHolderPublicKey, today: u64, nonce: &Vec<u8>, holder_sig: &AgeVerSignature) -> Result<AgeVerPresentation, AgeVerError> {
    let params = AgeVerParams::new();
    let presenter = AgeVerPresenter::new(&params, cred.clone(), holder_pk)?;
    Ok(presenter.present(today, nonce, holder_sig))
}

impl AgeVerPresenter {
    pub fn new(params: &AgeVerParams, cred: AgeVerCredential, holder_pk: &AgeVerHolderPublicKey) -> Result<Self, AgeVerError> {

        let reveal_idx = Scope::from_iter(vec![String::from("above18")]);
        let commit_idx = Scope::from_iter(vec![String::from("header"), String::from("name"), String::from("above16"), String::from("nbf"), String::from("exp"), String::from("holder_pk")]); // TODO: remove useless committed 

        let mut rng = rand::rngs::StdRng::from_entropy();
        let presenter = CommittedDisclosurePresenter::new(
            &mut rng,
            &params.0,
            &cred.0,
            reveal_idx,
            commit_idx,
            None
        ).map_err(|e| AgeVerError::PresentationError(e.to_string()))?;

        Ok(AgeVerPresenter { presenter,  holder_pk: holder_pk.clone() })
    }

    pub fn present(self, today: u64, nonce: &Vec<u8>, holder_sig: &AgeVerSignature) -> AgeVerPresentation {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let presentation = self.presenter.gen_presentation(
            &mut rng,
            today,
            &self.holder_pk.0,
            nonce,
            &holder_sig.0
        );

        AgeVerPresentation { presentation, today }
    }
}

pub struct AgeVerVerifier {
    verifier: CommittedDisclosureVerifier,
}

pub struct AgeVerIssuerPublicKey (IssuerPublicKey);

impl AgeVerIssuerPublicKey {

    pub fn from_keypair(issuer_pk: AgeVerIssuerKeyPair) -> Self {
        AgeVerIssuerPublicKey(issuer_pk.0.public_key.clone())
    }
}

impl AgeVerVerifier {
    pub fn new(params: &AgeVerParams,  issuer_pk : &AgeVerIssuerPublicKey) -> Self {
        let verifier = CommittedDisclosureVerifier::new(
            params.0.clone(),
            issuer_pk.0.clone()
        );
        AgeVerVerifier { verifier }
    }

    pub fn verify(&self, pres: &AgeVerPresentation, nonce: &Vec<u8>) -> bool { // TODO: add context

        let claims = vec![
            ("above18".to_string(), Claim::Bool(true)),
        ];

        let mut rng = rand::rngs::StdRng::from_entropy();
        self.verifier.verify_presentation(
            &mut rng,
            &pres.presentation,
            pres.today,
            nonce,
            claims,
            None).is_ok() 
        }
}

use base64::{engine::general_purpose::URL_SAFE as BASE64, Engine};

#[uniffi::export]
impl AgeVerCredential {
    pub fn to_jwt(&self) -> String {
        self.0.to_jwt()
    }

    pub fn claims_json_str(&self) -> String {
        self.0.claims_json_str()
    }
}

impl AgeVerCredential {
        pub fn from_jwt(jwt: &str) -> Result<Self, String>{
        let cred = Credential::from_jwt(jwt).map_err(|e| e.to_string())?;
        Ok(AgeVerCredential(cred))
    }
}

#[uniffi::export]
impl AgeVerPresentation {
    pub fn to_base64(&self) -> String {
        let mut bytes = Vec::new();
        self.serialize_compressed(&mut bytes).expect("serialization failed");
        BASE64.encode(&bytes)
    }
}

impl AgeVerPresentation {
    pub fn from_base64(s: &str) -> Result<Self, String> {
        let bytes = BASE64.decode(s).map_err(|e| e.to_string())?;
        Self::deserialize_compressed(&bytes[..]).map_err(|e| e.to_string())
    }
}

#[uniffi::export]
pub fn holder_pk_to_base64(pk: &AgeVerHolderPublicKey) -> String {
    let mut bytes = Vec::new();
    pk.0.serialize_compressed(&mut bytes).expect("serialization failed");
    BASE64.encode(&bytes)
}

#[uniffi::export]
pub fn holder_pk_from_bytes(bytes: Vec<u8>) -> Result<AgeVerHolderPublicKey, AgeVerError> {
    AgeVerHolderPublicKey::deserialize_compressed(&bytes[..]).map_err(|e| AgeVerError::DeserializationError(e.to_string()))
}


#[derive(Debug, uniffi::Error)]
pub enum AgeVerError {
    Base64DecodeError(String),
    SerializationError(String),
    DeserializationError(String),
    IssuanceError(String),
    PresentationError(String),
}

impl std::fmt::Display for AgeVerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgeVerError::Base64DecodeError(e) => write!(f, "Base64 decode error: {}", e),
            AgeVerError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            AgeVerError::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
            AgeVerError::IssuanceError(e) => write!(f, "Issuance error: {}", e),
            AgeVerError::PresentationError(e) => write!(f, "Presentation error: {}", e),

        }
    }
}

#[uniffi::export]
/// Constructs an `AgeVerHolderPublicKey` from an uncompressed SEC1 point (0x04 || x || y, 65 bytes).
/// This is the format used in X.509 SubjectPublicKeyInfo for P-256 keys.
pub fn holder_pk_from_uncompressed_sec1(bytes: &[u8]) -> Result<AgeVerHolderPublicKey, AgeVerError> {
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(AgeVerError::DeserializationError(
            "expected 65-byte uncompressed SEC1 point (0x04 || x || y)".into(),
        ));
    }
    let mut x_le = bytes[1..33].to_vec();
    x_le.reverse();
    let mut y_le = bytes[33..65].to_vec();
    y_le.reverse();
    let x = SecP256Fq::from_le_bytes_mod_order(&x_le);
    let y = SecP256Fq::from_le_bytes_mod_order(&y_le);
    Ok(AgeVerHolderPublicKey(HolderPublicKey::new_unchecked(x, y)))
}

pub fn holder_pk_from_base64(s: &str) -> Result<AgeVerHolderPublicKey, AgeVerError> {
    let bytes = BASE64.decode(s).map_err(|e| AgeVerError::Base64DecodeError(e.to_string()))?;
    AgeVerHolderPublicKey::deserialize_compressed(&bytes[..]).map_err(|e| AgeVerError::DeserializationError(e.to_string()))
}

#[uniffi::export]
pub fn credential_from_jwt(s: &str) -> Result<AgeVerCredential, AgeVerError> {
    let cred = Credential::from_jwt(s).map_err(|e| AgeVerError::DeserializationError(e.to_string()))?;
    Ok(AgeVerCredential(cred))
}

#[uniffi::export]
pub fn gen_holder_keypair() -> AgeVerHolderKeyPair {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let keypair = HolderKeyPair::new_from_rng(&mut rng);
    AgeVerHolderKeyPair(keypair)
}

#[uniffi::export]
pub fn gen_holder_sig(nonce: &Vec<u8>, holder_sk: &AgeVerHolderSecretKey) -> AgeVerSignature {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let nonce_digest = Sha256::digest(nonce);
    AgeVerSignature(ecdsa::Signature::new_prehashed(&mut rng, SecP256Fr::from_be_bytes_mod_order(&nonce_digest), holder_sk.0.clone()))
}

/// Returns the P-256 private scalar as big-endian bytes (32 bytes).
/// Useful for bridging to other crypto libraries (e.g. OpenSSL) in tests.
pub fn holder_sk_to_bytes(sk: &AgeVerHolderSecretKey) -> Vec<u8> {
    sk.0.into_bigint().to_bytes_be()
}

#[uniffi::export]
pub fn holder_sig_from_der_bytes(bytes: Vec<u8>) -> Result<AgeVerSignature, AgeVerError> {
    fn parse_der_len(input: &[u8], i: &mut usize) -> Result<usize, AgeVerError> {
        if *i >= input.len() {
            return Err(AgeVerError::DeserializationError("unexpected end while parsing DER length".to_string()));
        }

        let first = input[*i];
        *i += 1;

        if (first & 0x80) == 0 {
            return Ok(first as usize);
        }

        let octets = (first & 0x7f) as usize;
        if octets == 0 || octets > std::mem::size_of::<usize>() {
            return Err(AgeVerError::DeserializationError("invalid DER length encoding".to_string()));
        }
        if *i + octets > input.len() {
            return Err(AgeVerError::DeserializationError("unexpected end while parsing DER long-form length".to_string()));
        }

        let mut len: usize = 0;
        for b in &input[*i..*i + octets] {
            len = (len << 8) | (*b as usize);
        }
        *i += octets;
        Ok(len)
    }

    fn parse_der_integer(input: &[u8], i: &mut usize) -> Result<SecP256Fr, AgeVerError> {
        if *i >= input.len() || input[*i] != 0x02 {
            return Err(AgeVerError::DeserializationError("expected DER INTEGER".to_string()));
        }
        *i += 1;

        let len = parse_der_len(input, i)?;
        if len == 0 || *i + len > input.len() {
            return Err(AgeVerError::DeserializationError("invalid DER INTEGER length".to_string()));
        }

        let raw = &input[*i..*i + len];
        *i += len;

        if (raw[0] & 0x80) != 0 {
            return Err(AgeVerError::DeserializationError("negative DER INTEGER not allowed for ECDSA".to_string()));
        }
        if raw.len() > 1 && raw[0] == 0x00 && (raw[1] & 0x80) == 0 {
            return Err(AgeVerError::DeserializationError("non-canonical DER INTEGER encoding".to_string()));
        }

        let magnitude = if raw.len() > 1 && raw[0] == 0x00 {
            &raw[1..]
        } else {
            raw
        };

        if magnitude.is_empty() || magnitude.len() > 32 {
            return Err(AgeVerError::DeserializationError("DER INTEGER out of range for secp256r1 scalar".to_string()));
        }

        let fr = SecP256Fr::from_be_bytes_mod_order(magnitude);

        let mut canonical = fr.into_bigint().to_bytes_be();
        if canonical.is_empty() {
            canonical.push(0);
        }
        if canonical.as_slice() != magnitude {
            return Err(AgeVerError::DeserializationError("DER INTEGER is not a valid canonical secp256r1 scalar".to_string()));
        }

        if fr == SecP256Fr::from(0u64) {
            return Err(AgeVerError::DeserializationError("ECDSA scalar must be non-zero".to_string()));
        }

        Ok(fr)
    }

    let mut i = 0;
    if bytes.get(i) != Some(&0x30) {
        return Err(AgeVerError::DeserializationError("expected DER SEQUENCE".to_string()));
    }
    i += 1;

    let seq_len = parse_der_len(&bytes, &mut i)?;
    if i + seq_len != bytes.len() {
        return Err(AgeVerError::DeserializationError("DER SEQUENCE length mismatch".to_string()));
    }
    let seq_end = i + seq_len;

    let rand_x_coord = parse_der_integer(&bytes[..seq_end], &mut i)?;
    let response = parse_der_integer(&bytes[..seq_end], &mut i)?;

    if i != seq_end {
        return Err(AgeVerError::DeserializationError("trailing data in DER ECDSA signature".to_string()));
    }

    Ok(AgeVerSignature(Signature { rand_x_coord, response }))
}

// for testing
#[uniffi::export]
pub fn verify_holder_sig(nonce: &Vec<u8>, holder_pk: &AgeVerHolderPublicKey, sig: &AgeVerSignature) -> bool {
    let nonce_digest = Sha256::digest(nonce);
    sig.0.verify_prehashed(SecP256Fr::from_be_bytes_mod_order(&nonce_digest), holder_pk.0.clone())
}
