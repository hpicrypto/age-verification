// Caution: this code is mostly AI-generated, has not been carefully audited, and is used strictly 
// for demonstration purposes. Do not reuse this code.

use agever::holder_pk_from_uncompressed_sec1;
use axum::http::StatusCode;
use base64::{Engine, prelude::BASE64_STANDARD};
use openssl::{
    bn::BigNumContext,
    ec::PointConversionForm,
    stack::Stack,
    x509::{X509, X509StoreContext},
    x509::store::X509Store,
};

/// Minimal BER/DER TLV reader. Returns `(tag, value_bytes, remaining_input)`.
/// Handles both the short and definite long forms of length encoding.
fn der_read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first_len_byte, rest) = rest.split_first()?;
    let (len, rest) = if first_len_byte & 0x80 == 0 {
        (first_len_byte as usize, rest)
    } else {
        let n = (first_len_byte & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let mut l = 0usize;
        for &b in &rest[..n] {
            l = l.checked_shl(8)?.checked_add(b as usize)?;
        }
        (l, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// DER-encoded OID content bytes for 1.3.6.1.4.1.11129.2.1.17
/// (Android Key Attestation extension, Google).
const ANDROID_KEY_ATTESTATION_OID_BYTES: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x11];

/// Parses a DER-encoded X.509 certificate and returns the `extnValue` bytes
/// (OCTET STRING content = DER of the extension value) for the first extension
/// whose OID content bytes match `oid_content`.
///
/// This avoids the `openssl` crate's `extensions()` API, which is not available
/// on all platforms (e.g. macOS LibreSSL).
fn find_extension_in_cert_der(cert_der: &[u8], oid_content: &[u8]) -> Option<Vec<u8>> {
    // Certificate SEQUENCE → TBSCertificate (first child SEQUENCE)
    let (_, cert_body, _) = der_read_tlv(cert_der)?;
    let (_, tbs, _) = der_read_tlv(cert_body)?;

    // Scan TBSCertificate fields for [3] EXPLICIT Extensions (tag 0xa3).
    let mut rest = tbs;
    let extensions_explicit = loop {
        let (tag, value, tail) = der_read_tlv(rest)?;
        if tag == 0xa3 {
            break value;
        }
        rest = tail;
        if rest.is_empty() {
            return None;
        }
    };

    // [3] EXPLICIT wraps SEQUENCE OF Extension.
    let (_, exts_body, _) = der_read_tlv(extensions_explicit)?;

    let mut exts_rest = exts_body;
    while !exts_rest.is_empty() {
        let (_, ext, tail) = der_read_tlv(exts_rest)?;
        exts_rest = tail;

        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
        let (oid_tag, oid_val, after_oid) = der_read_tlv(ext)?;
        if oid_tag != 0x06 || oid_val != oid_content {
            continue;
        }

        // Skip optional critical BOOLEAN (0x01), then read extnValue OCTET STRING (0x04).
        let (tag1, val1, rest1) = der_read_tlv(after_oid)?;
        return if tag1 == 0x01 {
            // critical BOOLEAN present; extnValue follows
            let (_, octet_val, _) = der_read_tlv(rest1)?;
            Some(octet_val.to_vec())
        } else {
            // val1 is already the extnValue OCTET STRING content
            Some(val1.to_vec())
        };
    }
    None
}

/// Checks that the leaf certificate's Android Key Attestation extension reports
/// that the attested key is backed by StrongBox (`keymasterSecurityLevel == 2`).
///
/// Takes the raw DER of the leaf certificate. Must be called **after** the
/// certificate chain has been validated by OpenSSL.
fn check_strongbox_security_level(
    cert_der: &[u8],
) -> Result<(), (StatusCode, &'static str)> {
    const MALFORMED: (StatusCode, &'static str) =
        (StatusCode::BAD_REQUEST, "malformed Android Key Attestation extension");

    let ext_data =
        find_extension_in_cert_der(cert_der, ANDROID_KEY_ATTESTATION_OID_BYTES)
            .ok_or((StatusCode::BAD_REQUEST, "missing Android Key Attestation extension"))?;

    // Unwrap the outer KeyDescription SEQUENCE.
    let (tag, body, _) = der_read_tlv(&ext_data).ok_or(MALFORMED)?;
    if tag != 0x30 {
        return Err(MALFORMED);
    }

    // KeyDescription ::= SEQUENCE {
    //   attestationVersion       INTEGER,     -- skip (field 0)
    //   attestationSecurityLevel ENUMERATED,  -- skip (field 1)
    //   keymasterVersion         INTEGER,     -- skip (field 2)
    //   keymasterSecurityLevel   ENUMERATED,  -- read (field 3)
    //   ...
    // }
    let (_, _, rest) = der_read_tlv(body).ok_or(MALFORMED)?; // attestationVersion
    let (_, _, rest) = der_read_tlv(rest).ok_or(MALFORMED)?; // attestationSecurityLevel
    let (_, _, rest) = der_read_tlv(rest).ok_or(MALFORMED)?; // keymasterVersion
    let (tag, value, _) = der_read_tlv(rest).ok_or(MALFORMED)?;
    if tag != 0x0a {
        return Err(MALFORMED);
    }
    let level = value.first().copied().ok_or(MALFORMED)?;

    // SecurityLevel: Software = 0, TrustedEnvironment = 1, StrongBox = 2
    if level != 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            "key is not backed by Android StrongBox",
        ));
    }

    Ok(())
}

/// Verifies the certificate chain via OpenSSL (handles any algorithm mix, e.g. RSA
/// intermediates in an Android StrongBox attestation chain) and returns the holder's
/// P-256 public key extracted from the validated leaf certificate.
/// `cert_chain_b64` is ordered leaf-first; each entry is standard base64-encoded DER.
/// Verifies the certificate chain via OpenSSL PKIX validation and checks that the
/// leaf key is backed by Android StrongBox. Returns `Ok(())` on success.
/// Note that this function does not handle revocation checks.
pub fn verify_cert_chain(
    cert_chain_b64: &[String],
    store: &X509Store,
) -> Result<(), (StatusCode, &'static str)> {
    if cert_chain_b64.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "cert_chain must not be empty"));
    }

    let ders: Vec<Vec<u8>> = cert_chain_b64
        .iter()
        .map(|s| BASE64_STANDARD.decode(s))
        .collect::<Result<_, _>>()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid base64 in cert_chain"))?;

    let leaf = X509::from_der(&ders[0])
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid leaf certificate"))?;

    let mut intermediates = Stack::new().unwrap();
    for der in ders[1..].iter() {
        let cert = X509::from_der(der)
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid certificate in chain"))?;
        intermediates.push(cert).unwrap();
    }

    // Delegate the full PKIX path validation to OpenSSL.
    let mut ctx = X509StoreContext::new().unwrap();
    let mut verify_error = openssl::x509::X509VerifyResult::OK;
    let mut error_depth = 0u32;
    let valid = ctx
        .init(store, &leaf, &intermediates, |c| {
            let result = c.verify_cert()?;
            if !result {
                verify_error = c.error();
                error_depth = c.error_depth();
            }
            Ok(result)
        })
        .map_err(|e| {
            tracing::warn!(error = %e, "certificate chain verification failed (OpenSSL error)");
            (StatusCode::BAD_REQUEST, "certificate chain verification failed")
        })?;
    if !valid {
        tracing::warn!(
            verify_error = %verify_error,
            depth = error_depth,
            "certificate chain is not trusted"
        );
        return Err((StatusCode::BAD_REQUEST, "certificate chain is not trusted"));
    }

    // Check that the attested key is backed by StrongBox.
    // This must happen after chain validation so the extension can be trusted.
    check_strongbox_security_level(&ders[0])?;

    Ok(())
}

/// Extracts the holder's P-256 public key from the leaf certificate (index 0)
/// of `cert_chain_b64`, without any chain validation.
pub fn extract_holder_pk(
    cert_chain_b64: &[String],
) -> Result<agever::AgeVerHolderPublicKey, (StatusCode, &'static str)> {
    if cert_chain_b64.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "cert_chain must not be empty"));
    }
    let leaf_der = BASE64_STANDARD
        .decode(&cert_chain_b64[0])
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid base64 in cert_chain"))?;
    let leaf = X509::from_der(&leaf_der)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid leaf certificate"))?;
    let pkey = leaf
        .public_key()
        .map_err(|_| (StatusCode::BAD_REQUEST, "failed to extract leaf public key"))?;
    let ec_key = pkey
        .ec_key()
        .map_err(|_| (StatusCode::BAD_REQUEST, "leaf key is not an EC key"))?;
    let group = ec_key.group();
    let mut bnctx = BigNumContext::new().unwrap();
    let uncompressed = ec_key
        .public_key()
        .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut bnctx)
        .map_err(|_| (StatusCode::BAD_REQUEST, "failed to encode leaf public key"))?;
    holder_pk_from_uncompressed_sec1(&uncompressed)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "failed to import leaf public key"))
}
