use ark_std::rand::{SeedableRng, rngs::StdRng};
use rand::RngCore;
use axum::{
    Router, extract::{Form, Json, State}, http::{HeaderMap, StatusCode}, response::{Html, IntoResponse, Redirect}, routing::{get, post}
};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;
use base64::{Engine, prelude::BASE64_STANDARD};
use openssl::{
    x509::X509,
    x509::store::{X509Store, X509StoreBuilder},
};
use image::{ExtendedColorType, ImageEncoder, codecs::png::PngEncoder};
use qrcode::QrCode;
use agever::{AgeVerParams as Params,
     AgeVerIssuer as Issuer,
     AgeVerIssuerKeyPair as IssuerKeyPair,
     AgeVerIssuerPublicKey as IssuerPublicKey,
     AgeVerVerifier as Verifier,
     AgeVerPresentation as Presentation,
     AgeVerStatusManager as StatusManager,
     AgeVerStatusManagerKeyPair as StatusManagerKeyPair,
     AgeVerStatusManagerPublicKey as StatusManagerPublicKey,
     AgeVerRevocationParams as RevocationParams,
     AgeVerGapCredential as GapCredential};
use serde::Deserialize;
use axum_extra::extract::cookie::{Cookie, CookieJar};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

mod cert;
mod trust_anchors;
use crate::cert::{verify_cert_chain, extract_holder_pk};

struct AppState {
    sessions: Mutex<HashMap<String, bool>>,
    issuer: Issuer,
    verifier: Verifier,
    _params: Params,
    _keypair: IssuerKeyPair,
    trust_anchor_store: X509Store,
    /// When false, the StrongBox security-level check is skipped (emulator / test mode).
    require_attestation: bool,
    status_manager: StatusManager,
    revocation: Mutex<RevocationState>,
    /// When set, required (via the X-Admin-Secret header) to call /admin/revoke. When unset,
    /// the endpoint is open - matches require_attestation's permissive-unless-configured default.
    admin_secret: Option<String>,
}

struct RevocationState {
    epoch: u64,
    revoked: BTreeSet<u64>,
    gap_list: Vec<GapCredential>,
}

/// Synthetic revoked handles seeded at startup live at/above this value, far above the range of
/// real issued rev_handles (which start at 1 and increment by 1). Used to filter them out of the
/// human-readable /revocation-status view so a real revoke's effect isn't buried in the noise.
const SEED_REVOKED_BASE: u64 = 1_000_000;

type SharedState = Arc<AppState>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tower_http=info,web=info".into()),
        )
        .init();
    let state = build_state();
    let app = build_app(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

fn build_state() -> SharedState {
    let params = Params::new();
    let mut rng = match std::env::var("ISSUER_SECRET") {
        Ok(secret) => {
            let seed: [u8; 32] = secret.as_bytes().try_into()
                .unwrap_or_else(|_| panic!("ISSUER_SECRET must be exactly 32 bytes, had {})", secret.len()));
            StdRng::from_seed(seed)
        }
        Err(std::env::VarError::NotPresent) => StdRng::from_entropy(),
        Err(e) => panic!("ISSUER_SECRET env var is not valid UTF-8: {e}"),
    };
    let keypair = IssuerKeyPair::new(&mut rng);
    let issuer_pk = IssuerPublicKey::from_keypair(keypair.clone());

    let revocation_params = RevocationParams::new();
    let status_manager_keypair = StatusManagerKeyPair::new(&mut rng);
    let status_manager_pk = StatusManagerPublicKey::from_keypair(status_manager_keypair.clone());
    let status_manager = StatusManager::new(&revocation_params, status_manager_keypair);
    let initial_epoch = 1u64;

    // Seed the revocation list with a batch of synthetic handles so the demo starts with a
    // realistically large gap list instead of an empty one. These live far above the range of
    // real issued rev_handles (which start at 1 and increment by 1), so they never collide.
    let seed_count: u64 = std::env::var("SEED_REVOKED_COUNT")
        .ok()
        .map(|v| v.parse().unwrap_or_else(|e| panic!("SEED_REVOKED_COUNT must be a u64: {e}")))
        .unwrap_or(2_000);
    let seeded_revoked: BTreeSet<u64> = (SEED_REVOKED_BASE..SEED_REVOKED_BASE + seed_count).collect();

    let seed_start = std::time::Instant::now();
    let initial_gap_list = status_manager
        .revoke(initial_epoch, seeded_revoked.iter().cloned().collect())
        .expect("initial gap list generation failed");
    tracing::info!(
        count = seed_count,
        elapsed = ?seed_start.elapsed(),
        "seeded initial revocation gap list"
    );

    let admin_secret = std::env::var("ADMIN_SECRET").ok();

    // Load extra trust anchors from a PEM file when EXTRA_TRUST_CERTS_PEM_FILE is set.
    // Useful for emulator testing where the key attestation chain is rooted in a
    // different CA than the production Google roots.
    let extra_der_certs: Vec<Vec<u8>> = match std::env::var("EXTRA_TRUST_CERTS_PEM_FILE") {
        Ok(path) => {
            let pem = std::fs::read(&path)
                .unwrap_or_else(|e| panic!("cannot read EXTRA_TRUST_CERTS_PEM_FILE ({path}): {e}"));
            X509::stack_from_pem(&pem)
                .unwrap_or_else(|e| panic!("cannot parse EXTRA_TRUST_CERTS_PEM_FILE ({path}): {e}"))
                .into_iter()
                .map(|c| c.to_der().expect("cert to DER"))
                .collect()
        }
        Err(std::env::VarError::NotPresent) => vec![],
        Err(e) => panic!("EXTRA_TRUST_CERTS_PEM_FILE env var is not valid UTF-8: {e}"),
    };

    // When REQUIRE_ATTEST=false (or "0"), skip the Android StrongBox level check.
    // Needed for emulator builds which attest at security level 0 instead of 2.
    let require_attestation = std::env::var("REQUIRE_ATTEST")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);

    if !extra_der_certs.is_empty() {
        tracing::info!(
            count = extra_der_certs.len(),
            "loaded extra trust anchors from EXTRA_TRUST_CERTS_PEM_FILE"
        );
    }
    if !require_attestation {
        tracing::warn!("StrongBox attestation check is DISABLED (REQUIRE_ATTEST=false)");
    }

    Arc::new(AppState {
        sessions: Mutex::new(HashMap::new()),
        _params: params.clone(),
        _keypair: keypair.clone(),
        issuer: Issuer::new(&params, keypair.clone()),
        verifier: Verifier::new(&params, &issuer_pk, &revocation_params, &status_manager_pk),
        trust_anchor_store: build_trust_store(&extra_der_certs),
        require_attestation,
        status_manager,
        revocation: Mutex::new(RevocationState { epoch: initial_epoch, revoked: seeded_revoked, gap_list: initial_gap_list }),
        admin_secret,
    })
}

/// Builds an X509Store from the built-in Google Key Attestation root CAs plus any
/// caller-supplied extra DER-encoded certificates (e.g. emulator or test roots).
/// PARTIAL_CHAIN is enabled so that a single self-signed cert in the store is
/// accepted as a trust anchor without needing further chain building.
fn build_trust_store(extra_der_certs: &[Vec<u8>]) -> X509Store {
    use openssl::x509::verify::X509VerifyFlags;
    let mut store_builder = X509StoreBuilder::new().unwrap();
    store_builder.set_flags(X509VerifyFlags::PARTIAL_CHAIN).unwrap();
    for der in trust_anchors::default_trust_anchor_ders()
        .iter()
        .chain(extra_der_certs.iter())
    {
        let cert = X509::from_der(der).expect("trust anchor DER is not a valid certificate");
        store_builder.add_cert(cert).unwrap();
    }
    store_builder.build()
}

fn build_app(state: SharedState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/ageverification", get(ageverification))
        .route("/logout", get(logout))
        .route("/validate", post(validate))
        .route("/status", get(status))
        .route("/issue", post(issue))
        .route("/revocation-status", get(revocation_status))
        .route("/admin/revoke", post(admin_revoke))
        .layer(
            // DEBUG, not INFO: per-request tracing (including routine polling like the QR
            // page's 1s /status loop) would otherwise flood the default log. The app's own
            // tracing::info! calls (issue/revoke/validate) still show at the default level;
            // opt into full request tracing with RUST_LOG=tower_http=debug when needed.
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::DEBUG))
                .on_response(DefaultOnResponse::new().level(Level::DEBUG)),
        )
        .with_state(state)
}

async fn index(State(state): State<SharedState>, jar: CookieJar) -> impl IntoResponse {
    let validated = jar
        .get("session_id")
        .map(|c| state.sessions.lock().unwrap().get(c.value()).copied() == Some(true))
        .unwrap_or(false);

    if validated {
        let id = jar.get("session_id").unwrap().value().to_string();
        Html(welcome_html(&id)).into_response()
    } else {
        Html(login_html()).into_response()
    }
}

async fn ageverification(State(state): State<SharedState>, jar: CookieJar) -> impl IntoResponse {
    if let Some(c) = jar.get("session_id") {
        let sessions = state.sessions.lock().unwrap();
        if sessions.get(c.value()).copied() == Some(true) {
            drop(sessions);
            return Redirect::to(".").into_response();
        }
        if sessions.contains_key(c.value()) {
            let id = c.value().to_string();
            drop(sessions);
            return (jar, Html(pending_html(&id))).into_response();
        }
    }

    let id = Uuid::new_v4().to_string();
    state.sessions.lock().unwrap().insert(id.clone(), false);
    let jar = jar.add(Cookie::new("session_id", id.clone()));
    (jar, Html(pending_html(&id))).into_response()
}

async fn logout(State(state): State<SharedState>, jar: CookieJar) -> impl IntoResponse {
    if let Some(c) = jar.get("session_id") {
        state.sessions.lock().unwrap().remove(c.value());
    }
    let jar = jar.remove(Cookie::from("session_id"));
    (jar, Redirect::to("."))
}

#[derive(Deserialize, Debug)]
struct IssueRequest {
    /// Certificate chain, leaf first. Each entry is standard base64-encoded DER.
    cert_chain: Vec<String>
}

async fn issue(
    State(state): State<SharedState>,
    Json(req): Json<IssueRequest>,
) -> impl IntoResponse {
    tracing::info!("issue request received");

    let chain_result = verify_cert_chain(&req.cert_chain, &state.trust_anchor_store);
    if let Err((_, msg)) = chain_result {
        if state.require_attestation {
            return (StatusCode::BAD_REQUEST, msg).into_response();
        }
        tracing::info!(error = msg, "attestation check failed but proceeding (require_attestation=false)");
    }

    let holder_pk = match extract_holder_pk(&req.cert_chain) {
        Ok(pk) => pk,
        Err((code, msg)) => return (code, msg).into_response(),
    };

    // Sampled uniformly from the full u64 space rather than assigned sequentially, so the
    // handle can't be used to infer issuance order or volume.
    let rev_handle = rand::thread_rng().next_u64();
    tracing::info!(rev_handle, "issuing credential");

    let cred = state.issuer.issue_credential("John Doe".to_string(), 20, holder_pk, rev_handle);
    match cred {
        Ok(c) => c.to_jwt().into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("credential issuance failed: {e:?}")).into_response(),
    }
}

async fn validate(
    State(state): State<SharedState>,
    Form(form): Form<ValidateForm>,
) -> impl IntoResponse {
    tracing::info!(session_id = %form.session_id, token = "[skipped]", "validate form received");

    if !state.sessions.lock().unwrap().contains_key(&form.session_id) {
        return (StatusCode::NOT_FOUND, "session not found").into_response();
    }

    // decodes token from standard base64:
    let pres = match Presentation::from_base64(&form.token) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid token encoding").into_response(),
    };

    // checks that the presentation time is not further than 60 sec.
    if pres.today.abs_diff(chrono::Utc::now().timestamp() as u64) > 60 {
        return (StatusCode::BAD_REQUEST, "invalid token: presentation time is too far from current time").into_response();
    }

    let nonce = format!("demo-nonce-{}", form.session_id).as_bytes().to_vec(); // In a real application, this should be a unique value generated for each session and included in the QR code.
    let epoch = { state.revocation.lock().unwrap().epoch };
    if !state.verifier.verify(&pres, &nonce, epoch) {
        return (StatusCode::BAD_REQUEST, "invalid token").into_response();
    }

    state.sessions.lock().unwrap().insert(form.session_id, true);

    "validated".into_response()
}

#[derive(Deserialize, Debug)]
struct ValidateForm {
    session_id: String,
    token: String,
}

async fn revocation_status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let rev = state.revocation.lock().unwrap();
    let real_revoked: Vec<u64> = rev.revoked.iter().copied().filter(|h| *h < SEED_REVOKED_BASE).collect();
    let seeded_count = rev.revoked.len() - real_revoked.len();
    Json(serde_json::json!({
        "epoch": rev.epoch,
        "revoked_handles": real_revoked,
        "seeded_synthetic_revoked_count": seeded_count,
        "gaps": rev.gap_list.iter().map(|g| g.to_jwt()).collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize, Debug)]
struct RevokeRequest {
    rev_handle: u64,
}

/// Constant-time byte comparison, used to check the X-Admin-Secret header without leaking
/// timing information about how much of the secret matched.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn admin_revoke(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<RevokeRequest>,
) -> impl IntoResponse {
    if let Some(expected) = &state.admin_secret {
        let provided = headers.get("x-admin-secret").and_then(|v| v.to_str().ok());
        let ok = provided.map(|p| constant_time_eq(p.as_bytes(), expected.as_bytes())).unwrap_or(false);
        if !ok {
            return (StatusCode::UNAUTHORIZED, "invalid or missing X-Admin-Secret").into_response();
        }
    }

    let mut rev = state.revocation.lock().unwrap();
    rev.revoked.insert(req.rev_handle);
    rev.epoch += 1;
    tracing::info!(rev_handle = req.rev_handle, epoch = rev.epoch, "revoking handle");
    let new_gap_list = match state.status_manager.revoke(rev.epoch, rev.revoked.iter().cloned().collect()) {
        Ok(list) => list,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("re-signing gap list failed: {e:?}")).into_response(),
    };
    rev.gap_list = new_gap_list;

    Json(serde_json::json!({ "epoch": rev.epoch })).into_response()
}

async fn status(State(state): State<SharedState>, jar: CookieJar) -> Json<serde_json::Value> {
    let validated = jar
        .get("session_id")
        .map(|c| {
            state.sessions
                .lock()
                .unwrap()
                .get(c.value())
                .copied()
                .unwrap_or(false)
        })
        .unwrap_or(false);
    Json(serde_json::json!({ "validated": validated }))
}


fn qr_png_base64(data: &str) -> String {
    let code = QrCode::new(data.as_bytes()).unwrap();
    let img = code.render::<image::Luma<u8>>().min_dimensions(200, 200).build();
    let mut buf = Vec::new();
    PngEncoder::new(&mut buf)
        .write_image(img.as_raw(), img.width(), img.height(), ExtendedColorType::L8)
        .unwrap();
    BASE64_STANDARD.encode(&buf)
}

fn pending_html(session_id: &str) -> String {
    let qr_data = format!(r#"{{"sessid":"{}"}}"#, session_id);
    let qr_b64 = qr_png_base64(&qr_data);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Pending Validation</title>
  <style>
    body {{ font-family: sans-serif; max-width: 600px; margin: 4rem auto; text-align: center; }}
    code {{ background: #f0f0f0; padding: 0.2em 0.4em; border-radius: 4px; font-size: 1.1em; }}
    .hint {{ margin-top: 2rem; color: #888; font-size: 0.9em; }}
    img {{ margin-top: 1.5rem; image-rendering: pixelated; }}
    .btn {{ display: inline-block; margin-top: 1.5rem; padding: 0.6em 1.4em; background: #1a73e8; color: #fff; text-decoration: none; border-radius: 6px; font-size: 1em; }}
    .btn:hover {{ background: #1558b0; }}
  </style>
</head>
<body>
  <h1>Session Pending Validation</h1>
  <p>Your session ID is: <code>{session_id}</code></p>
  <img src="data:image/png;base64,{qr_b64}" alt="QR code" width="200" height="200">
  <br />
  <a class="btn" href="demowallet://verify?sessid={session_id}">Open in wallet app</a>
  <p id="dot">Waiting for validation…</p>
  <script>
    setInterval(async () => {{
      const res = await fetch('status');
      const data = await res.json();
      if (data.validated) window.location.href = '.';
    }}, 1000);
  </script>
</body>
</html>"#
    )
}

fn welcome_html(session_id: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Welcome</title>
  <style>
    body {{ font-family: sans-serif; max-width: 600px; margin: 4rem auto; text-align: center; }}
    code {{ background: #f0f0f0; padding: 0.2em 0.4em; border-radius: 4px; }}
    a {{ color: #c00; }}
  </style>
</head>
<body>
  <h1>Welcome!</h1>
  <p>Session <code>{session_id}</code> has been validated.</p>
  <p><a href="logout">Log out</a></p>
</body>
</html>"#
    )
}

fn login_html() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Age Verification</title>
  <style>
    body { font-family: sans-serif; max-width: 600px; margin: 4rem auto; text-align: center; }
    a { color: #00c; font-size: 1.1em; }
  </style>
</head>
<body>
  <h1>Age Verification Required</h1>
  <p>You must verify your age to continue.</p>
  <p><a href="ageverification">Verify my age</a></p>
</body>
</html>"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agever::{AgeVerPresenter, holder_sk_to_bytes};
    use axum::body::Body;
    use agever::{
        AgeVerCredential as Credential,
        gen_holder_keypair,
        gen_holder_sig,
        gap_credential_from_jwt,
        find_bracket,
    };
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    // Extract the session ID value from a Set-Cookie header like "session_id=abc; Path=/"
    fn extract_session_id(response: &axum::response::Response) -> String {
        let set_cookie = response.headers()["set-cookie"].to_str().unwrap();
        set_cookie
            .split(';').next().unwrap()
            .split('=').nth(1).unwrap()
            .to_string()
    }

    async fn body_string(response: axum::response::Response) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// Creates a P-256 self-signed X.509 certificate DER from raw key material.
    /// `pk_uncompressed`: uncompressed SEC1 public key (0x04 || x || y, 65 bytes).
    /// `sk_scalar_be`: private scalar as big-endian 32 bytes.
    fn make_self_signed_cert_der(pk_uncompressed: &[u8], sk_scalar_be: &[u8]) -> Vec<u8> {
        use openssl::{
            asn1::{Asn1Integer, Asn1Time},
            bn::{BigNum, BigNumContext},
            ec::{EcGroup, EcKey, EcPoint},
            hash::MessageDigest,
            nid::Nid,
            pkey::PKey,
            x509::{X509Builder, X509NameBuilder},
        };
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut bnctx = BigNumContext::new().unwrap();
        let private_bn = BigNum::from_slice(sk_scalar_be).unwrap();
        let public_point = EcPoint::from_bytes(&group, pk_uncompressed, &mut bnctx).unwrap();
        let ec_key = EcKey::from_private_components(&group, &private_bn, &public_point).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_nid(Nid::COMMONNAME, "test-holder").unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        let serial_bn = BigNum::from_u32(1).unwrap();
        let serial = Asn1Integer::from_bn(&serial_bn).unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(3650).unwrap()).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        builder.build().to_der().unwrap()
    }

    /// Builds a test AppState with a freshly generated holder keypair whose
    /// self-signed cert is the sole trust anchor, and attestation checks disabled.
    /// Returns: (shared state, holder keypair, base64-DER of self-signed cert).
    fn build_test_state_with_cert(admin_secret: Option<&str>) -> (SharedState, agever::AgeVerHolderKeyPair, String) {
        use openssl::{
            bn::{BigNum, BigNumContext},
            ec::{EcGroup, EcPoint, PointConversionForm},
            nid::Nid,
        };
        let params = Params::new();
        let mut rng = StdRng::from_seed(
            "dde5262705c68d2dbc4ad35c7b1738a1".as_bytes().try_into().unwrap(),
        );
        let issuer_keypair = IssuerKeyPair::new(&mut rng);
        let issuer_pk = IssuerPublicKey::from_keypair(issuer_keypair.clone());

        let revocation_params = RevocationParams::new();
        let status_manager_keypair = StatusManagerKeyPair::new(&mut rng);
        let status_manager_pk = StatusManagerPublicKey::from_keypair(status_manager_keypair.clone());
        let status_manager = StatusManager::new(&revocation_params, status_manager_keypair);
        let initial_epoch = 1u64;
        let initial_gap_list = status_manager.revoke(initial_epoch, vec![]).expect("initial gap list generation failed");

        let holder_keypair = gen_holder_keypair();

        // Derive the P-256 public key (uncompressed SEC1) from the private scalar via OpenSSL.
        let sk_bytes = holder_sk_to_bytes(&holder_keypair.secret_key());
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let private_bn = BigNum::from_slice(&sk_bytes).unwrap();
        let mut bnctx = BigNumContext::new().unwrap();
        let mut public_point = EcPoint::new(&group).unwrap();
        public_point.mul_generator(&group, &private_bn, &bnctx).unwrap();
        let pk_uncompressed = public_point
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut bnctx)
            .unwrap();

        let cert_der = make_self_signed_cert_der(&pk_uncompressed, &sk_bytes);
        let cert_b64 = BASE64_STANDARD.encode(&cert_der);

        let state = Arc::new(AppState {
            sessions: Mutex::new(HashMap::new()),
            _params: params.clone(),
            _keypair: issuer_keypair.clone(),
            issuer: Issuer::new(&params, issuer_keypair.clone()),
            verifier: Verifier::new(&params, &issuer_pk, &revocation_params, &status_manager_pk),
            trust_anchor_store: build_trust_store(&[cert_der]),
            require_attestation: false,
            status_manager,
            revocation: Mutex::new(RevocationState { epoch: initial_epoch, revoked: BTreeSet::new(), gap_list: initial_gap_list }),
            admin_secret: admin_secret.map(String::from),
        });

        (state, holder_keypair, cert_b64)
    }

    #[tokio::test]
    async fn test_get_index_no_session() {
        let app = build_app(build_state());
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("set-cookie"));
        let body = body_string(response).await;
        assert!(body.contains("ageverification"));
    }

    #[tokio::test]
    async fn test_ageverification_creates_session() {
        let app = build_app(build_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ageverification")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("set-cookie"));
        let body = body_string(response).await;
        assert!(body.contains("Pending"));
    }

    #[tokio::test]
    async fn test_token_issue() {
        let (state, _holder_keypair, cert_b64) = build_test_state_with_cert(None);
        let app = build_app(state);

        let body = serde_json::json!({ "cert_chain": [cert_b64] }).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/issue")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = body_string(response).await;
        println!("{:?}", body);
        assert_eq!(status, StatusCode::OK);
        let _token = Credential::from_jwt(&body).unwrap();
    }

    #[tokio::test]
    async fn test_validate_and_welcome() {
        let (state, holder_keypair, cert_b64) = build_test_state_with_cert(None);

        // Step 0: get a credential via /issue
        let issue_body = serde_json::json!({ "cert_chain": [cert_b64] }).to_string();
        let response = build_app(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/issue")
                    .header("content-type", "application/json")
                    .body(Body::from(issue_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cred = Credential::from_jwt(&body_string(response).await).unwrap();

        // Step 1: GET /ageverification to create a session
        let response = build_app(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .uri("/ageverification")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let session_id = extract_session_id(&response);

        // Step 2: fetch the current gap list and find the one that brackets our own handle
        let revocation_status_response = build_app(Arc::clone(&state))
            .oneshot(Request::builder().uri("/revocation-status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(revocation_status_response.status(), StatusCode::OK);
        let revocation_status_json: serde_json::Value =
            serde_json::from_str(&body_string(revocation_status_response).await).unwrap();
        let gaps: Vec<Arc<GapCredential>> = revocation_status_json["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|jwt| Arc::new(gap_credential_from_jwt(jwt.as_str().unwrap()).unwrap()))
            .collect();
        let rev_handle = cred.rev_handle().unwrap();
        let bracket = find_bracket(gaps, rev_handle).expect("should find a bracketing gap");

        // Step 3: POST /validate with presentation
        let revocation_params = RevocationParams::new();
        let presenter =
            AgeVerPresenter::new(&state._params, cred, &holder_keypair.public_key(), &revocation_params, &bracket).unwrap();
        let nonce = "demo-nonce".as_bytes().to_vec();
        let sig = gen_holder_sig(&nonce, &holder_keypair.secret_key());
        let today = chrono::Utc::now().timestamp() as u64;
        let pres = presenter.present(today, &nonce, &sig).unwrap();
        let pres_b64 = pres.to_base64();

        let body = format!("session_id={session_id}&token={pres_b64}");
        let response = build_app(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Step 4: GET / with session cookie — should show Welcome
        let response = build_app(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("cookie", format!("session_id={session_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(body.contains("Welcome"));

        // Step 5: revoke some other handle (bumping the epoch) and confirm the same,
        // now-stale presentation is rejected on a fresh /validate call.
        let revoke_response = build_app(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/revoke")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({ "rev_handle": rev_handle + 1000 }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoke_response.status(), StatusCode::OK);

        let stale_body = format!("session_id={session_id}&token={pres_b64}");
        let stale_response = build_app(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(stale_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stale_response.status(), StatusCode::BAD_REQUEST, "stale presentation should be rejected after epoch bump");
    }

    #[tokio::test]
    async fn test_admin_revoke_guard() {
        let (state, _holder_keypair, _cert_b64) = build_test_state_with_cert(Some("test-secret"));

        let revoke_body = serde_json::json!({ "rev_handle": 42u64 }).to_string();

        // No header: rejected.
        let response = build_app(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/revoke")
                    .header("content-type", "application/json")
                    .body(Body::from(revoke_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Correct header: accepted, epoch bumped.
        let response = build_app(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/revoke")
                    .header("content-type", "application/json")
                    .header("x-admin-secret", "test-secret")
                    .body(Body::from(revoke_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(&body_string(response).await).unwrap();
        assert_eq!(body["epoch"], 2);
    }
}
