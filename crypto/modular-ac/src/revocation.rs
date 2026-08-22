//! Non-revocation via "signed pairs": the issuer signs the *gaps* between revoked
//! identifiers instead of maintaining a revocation list to look holders up in. Every
//! credential gets a hidden `rev_handle` (UID) attribute. A holder proves, in
//! zero-knowledge, that it holds a validly-signed gap credential `(epoch, rid_lo, rid_hi)`
//! and that its own hidden `rev_handle` sits strictly between the gap's hidden endpoints
//! `rid_lo` and `rid_hi` - without revealing `rev_handle`, `rid_lo`, or `rid_hi`.
//!
//! The "hidden value strictly between two other hidden values" proof is built from the
//! homomorphic-subtraction trick over Pedersen commitments: if `C_a`, `C_b` are Pedersen
//! commitments (under a shared basis `(G, H)`) to values `a` and `b`, then `C_a - C_b - G`
//! is a commitment to `a - b - 1`, which is `>= 0` (provable via a Bulletproofs++ range
//! proof) exactly when `a > b`. Applying this twice - once for `rev_handle > rid_lo` and
//! once for `rid_hi > rev_handle` - and aggregating both range proofs into one
//! Bulletproofs++ call gives the non-revocation proof below.
//!
//! For this to work, the commitments to `rev_handle` (produced under the age credential's
//! `Params`) and to `rid_lo`/`rid_hi` (produced under the gap credential's own, independently
//! constructed `Params`) must share the same `(G, H)` basis. See the comment on `Params::new`
//! for why that's already guaranteed without any extra plumbing.

use crate::{Claim, CommittedDisclosure, CommittedDisclosurePresenter, CommittedDisclosureVerifier, Error, IndexMap};

use ark_bls12_381::G1Affine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use bulletproofs_plus_plus::prelude::{Proof as BppProof, Prover as BppProver};
use dock_crypto_utils::transcript::new_merlin_transcript;

/// The credential schema field holding a credential's hidden revocation handle (UID).
/// Always committed, never revealed - same treatment as `nbf`/`exp`.
pub const REV_HANDLE_FIELD: &str = "rev_handle";
/// The gap credential's lower (hidden) endpoint field.
pub const GAP_LO_FIELD: &str = "rid_lo";
/// The gap credential's upper (hidden) endpoint field.
pub const GAP_HI_FIELD: &str = "rid_hi";
/// The gap credential's (revealed) epoch field, used by verifiers to check freshness.
pub const GAP_EPOCH_FIELD: &str = "epoch";

/// A proof that a credential's hidden `rev_handle` has not been revoked: a disclosure of a
/// gap credential (epoch revealed, its two endpoints only committed-to) plus a raw aggregate
/// Bulletproofs++ proof that the age credential's hidden `rev_handle` lies strictly between
/// the gap's hidden endpoints.
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofOfNonRevocation {
    pub gap_disclosure: CommittedDisclosure,
    pub bpp_proof: BppProof<G1Affine>,
}

/// The Merlin transcript label for the aggregate Bulletproofs++ proof below.
const NON_REVOCATION_TRANSCRIPT_LABEL: &[u8] = b"non-revocation proof";

impl CommittedDisclosurePresenter {
    /// Builds a non-revocation proof against a specific gap credential, disclosed via
    /// `gap_presenter`. `gap_presenter` must have been constructed (via
    /// `CommittedDisclosurePresenter::new`) with `epoch` revealed and `rid_lo`/`rid_hi`
    /// committed, over a `Params` whose schema uses `GAP_LO_FIELD`/`GAP_HI_FIELD`/
    /// `GAP_EPOCH_FIELD`. `self` must have `REV_HANDLE_FIELD` committed.
    ///
    /// Panics if `self`'s schema has no `rev_handle` field, if `gap_presenter`'s schema has
    /// no `rid_lo`/`rid_hi` fields, or if the underlying claims aren't `Claim::Raw`.
    pub fn gen_non_revocation_proof<R: RngCore>(
        &self,
        rng: &mut R,
        gap_presenter: &CommittedDisclosurePresenter,
    ) -> ProofOfNonRevocation {
        let gap_disclosure = gap_presenter.gen_base_proof(rng);

        let uid_idx = self.params.schema.get(&REV_HANDLE_FIELD.to_string()).expect("rev_handle not found in schema").start;
        let lo_idx = gap_presenter.params.schema.get(&GAP_LO_FIELD.to_string()).expect("rid_lo not found in gap schema").start;
        let hi_idx = gap_presenter.params.schema.get(&GAP_HI_FIELD.to_string()).expect("rid_hi not found in gap schema").start;

        let uid = raw_claim_value(&self.cred.claims, REV_HANDLE_FIELD);
        let rid_lo = raw_claim_value(&gap_presenter.cred.claims, GAP_LO_FIELD);
        let rid_hi = raw_claim_value(&gap_presenter.cred.claims, GAP_HI_FIELD);

        let c_uid = self.committed_com[&uid_idx];
        let c_lo = gap_presenter.committed_com[&lo_idx];
        let c_hi = gap_presenter.committed_com[&hi_idx];

        let g = self.params.bpp_params.G.into_group();
        let d1 = (c_uid.into_group() - c_lo.into_group() - g).into_affine();
        let d2 = (c_hi.into_group() - c_uid.into_group() - g).into_affine();

        let r_uid = self.committed_opennings[&uid_idx];
        let r_lo = gap_presenter.committed_opennings[&lo_idx];
        let r_hi = gap_presenter.committed_opennings[&hi_idx];

        let mut transcript = new_merlin_transcript(NON_REVOCATION_TRANSCRIPT_LABEL);
        let bpp_proof = BppProver::new(
            crate::BPP_BITSIZE,
            vec![d1, d2],
            vec![uid - rid_lo - 1, rid_hi - uid - 1],
            vec![r_uid - r_lo, r_hi - r_uid],
        )
        .expect("BPP prover init failed")
        .prove(rng, self.params.bpp_params.clone(), &mut transcript)
        .expect("non-revocation BPP proof generation failed");

        ProofOfNonRevocation { gap_disclosure, bpp_proof }
    }
}

impl CommittedDisclosureVerifier {
    /// Verifies a non-revocation proof. `commitments` is the age credential's own committed-
    /// disclosure commitment map (i.e. `pres.committed_disclosure.commitments`).
    /// `gap_verifier` must be configured with the Status Manager's public key and a `Params`
    /// using the gap schema. `epoch` is the epoch the verifier currently considers current
    /// (freshness of `epoch` itself, e.g. "was this gap list re-signed recently enough", is a
    /// policy decision left to the caller - this only checks the proof is internally
    /// consistent with the given epoch).
    pub fn verify_non_revocation_proof<R: RngCore>(
        &self,
        rng: &mut R,
        commitments: &IndexMap<G1Affine>,
        gap_verifier: &CommittedDisclosureVerifier,
        epoch: u64,
        proof: &ProofOfNonRevocation,
    ) -> Result<(), Error> {
        gap_verifier.verify(rng, &proof.gap_disclosure, &vec![(GAP_EPOCH_FIELD.to_string(), Claim::Raw(epoch))], None)?;

        let uid_idx = self.params.schema.get(&REV_HANDLE_FIELD.to_string()).expect("rev_handle not found in schema").start;
        let lo_idx = gap_verifier.params.schema.get(&GAP_LO_FIELD.to_string()).expect("rid_lo not found in gap schema").start;
        let hi_idx = gap_verifier.params.schema.get(&GAP_HI_FIELD.to_string()).expect("rid_hi not found in gap schema").start;

        let c_uid = commitments[&uid_idx];
        let c_lo = proof.gap_disclosure.commitments[&lo_idx];
        let c_hi = proof.gap_disclosure.commitments[&hi_idx];

        let g = self.params.bpp_params.G.into_group();
        let d1 = (c_uid.into_group() - c_lo.into_group() - g).into_affine();
        let d2 = (c_hi.into_group() - c_uid.into_group() - g).into_affine();

        let mut transcript = new_merlin_transcript(NON_REVOCATION_TRANSCRIPT_LABEL);
        proof
            .bpp_proof
            .verify(crate::BPP_BITSIZE, &[d1, d2], &self.params.bpp_params, &mut transcript)
            .map_err(|e| Error::VerificationFailed(format!("non-revocation proof failed: {:?}", e)))
    }
}

fn raw_claim_value(claims: &std::collections::BTreeMap<String, Claim>, field: &str) -> u64 {
    match claims.get(field) {
        Some(Claim::Raw(v)) => *v,
        _ => panic!("claim '{field}' missing or not a Claim::Raw value"),
    }
}
