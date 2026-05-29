use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, BigInteger, BigInteger256, PrimeField, Zero};
pub use ark_secp256r1::{Affine as SecP256Affine, Fq as SecP256Fq, Fr as SecP256Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::{RngCore,rngs::StdRng},
    UniformRand,
};

use bbs_plus::setup::{PublicKeyG2, SignatureParams23G1};
use bbs_plus::signature_23::Signature23G1;
use bbs_plus::setup::KeypairG2;
use bulletproofs_plus_plus::prelude::SetupParams as BppSetupParams;
use dock_crypto_utils::{
    commitment::PedersenCommitmentKey, randomized_mult_checker::RandomizedMultChecker, transcript::{Transcript, new_merlin_transcript}
};
use dock_crypto_utils::hashing_utils::hash_to_field;

use equality_across_groups::{
    ec::commitments::{PointCommitment, PointCommitmentWithOpening, from_base_field_to_scalar_field},
    eq_across_groups,
    pok_ecdsa_pubkey::{PoKEcdsaSigCommittedPublicKey, PoKEcdsaSigCommittedPublicKeyProtocol, TransformedEcdsaSig}, 
    tom256::{ Affine as Tom256Affine, Fr as Tom256Fr, Projective as Tom256Projective}
};
use proof_system::{
    prelude::{
        bbs_23::PoKBBSSignature23G1Verifier, EqualWitnesses, MetaStatements, ProofSpec,
    },
    proof::Proof,
    statement::{
        Statements,
        bbs_23::PoKBBSSignature23G1Prover,
        ped_comm::PedersenCommitment as PedersenCommitmentStmt, 
        bound_check_bpp::{ BoundCheckBpp as BoundCheckStmt},
    },
    witness::{PoKBBSSignature23G1, Witness, Witnesses},
};
pub use kvac::bbs_sharp::ecdsa;
use core::panic;
use std::{ops::Range, string, vec};
use sha2::{Digest, Sha256};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Debug, Clone)]
/// The parameters for the committed disclosure of messages in BBS signatures.
pub struct Params {
    pub schema: Schema,
    pub sig_params: SignatureParams23G1<Bls12_381>,
    pub comm_key: PedersenCommitmentKey<G1Affine>,
    pub bpp_params: BppSetupParams<G1Affine>,

    pub comm_key_p256: PedersenCommitmentKey<SecP256Affine>,
    pub comm_key_tom256: PedersenCommitmentKey<Tom256Affine>,
}

/// A presenter-side struct for building modular presentations of anonymous credentials over BBS signatures.
pub struct CommittedDisclosurePresenter {
    pub params: Params,
    pub cred : Credential,
    pub revealed: IndexMap<Fr>,
    pub committed_msgs: IndexMap<Fr>,
    pub committed_com: IndexMap<G1Affine>,
    pub committed_opennings: IndexMap<Fr>,
    pub context : Vec<u8>,
}

/// A verifier-side struct for verifying modular presentations of anonymous credentials over BBS signatures.
pub struct CommittedDisclosureVerifier {
    pub params: Params,
    pk : IssuerPublicKey,
    // pres : CommittedDisclosure,
    // context: Vec<u8>,
}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
/// A proof of knowledge of a BBS signature on multiple messages, where some messages are revealed and some are committed to.
/// The proof asserts that the committed messages are the same as the messages in the signature.
pub struct CommittedDisclosure {
    //pub revealed: IndexMap<Claim>, // TODO: probably comming from somewhere else
    pub commitments: IndexMap<G1Affine>,
    pub proof: Proof<Bls12_381>,
}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
/// A proof that a credential is valid at the current time, i.e., that the current time 
/// is between the `nbf` and `exp` fields in the credential.
pub struct ProofOfValidty {
    proof: Proof<Bls12_381>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
/// A proof that a holder of a credential is able to create valid signature for a public key that is included in the credential. 
pub struct ProofOfPossession {
    comms: Vec<Tom256Affine>,
    eq_proofs: Vec<EqualProof>,
    sig_proof: SigProof,
}


#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
/// A presentation of a credential, consisting of a committed disclosure of messages in the credential, 
/// a proof of validity of the credential, and a proof of possession of the credential by the holder.
pub struct Presentation {
    pub committed_disclosure: CommittedDisclosure,
    pub validity_proof: ProofOfValidty,
    pub holder_binding_proof: ProofOfPossession,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Error {
    /// The number of provided messages is not equal to the number of messages supported by the signature params.
    InvalidMsgCount(usize, usize),
    /// A provided message id is not in the schema.
    InvalidMsgIdx(String),
    /// A message is not valid for the schema (wrong number of fields).
    InvalidMsg(String, usize, usize), // field name, provided, expected
    /// The reveal and commit indices are not disjoint.
    NonDisjointRevealAndCommitIndices, 
    /// The verification of the proof failed.
    VerificationFailed(string::String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidMsgCount(provided, expected) => write!(f, "invalid message count: provided {provided}, expected {expected}"),
            Error::InvalidMsgIdx(idx) => write!(f, "invalid message index: {idx}"),
            Error::InvalidMsg(field, provided, expected) => write!(f, "invalid message '{field}': provided {provided} fields, expected {expected}"),
            Error::NonDisjointRevealAndCommitIndices => write!(f, "reveal and commit indices are not disjoint"),
            Error::VerificationFailed(msg) => write!(f, "verification failed: {msg}"),
        }
    }
}

/// A set of messages indexes.
pub type Scope = BTreeSet<String>;

/// A map of message index -> value.
pub type IndexMap<V> = BTreeMap<usize, V>;

#[derive(Debug, Clone)]
/// A schema maps attribute names to message indexes in the credential.
pub struct Schema {
    pub version: u32,
    pub fields: BTreeMap<String, Range<usize>>
}



#[derive(Debug, Clone)]
pub enum Claim {
    Value(String),
    Bool(bool),
    Raw(u64),
    HolderPk(HolderPublicKey),
}

impl Claim {
    pub fn to_field(&self) -> Vec<Fr> {


        match self {
            Claim::Value(s) => vec![hash_to_field::<Fr, Sha256>(b"", s.as_bytes())],
            Claim::Bool(b) => if *b { vec![Params::msg_true()] } else { vec![Params::msg_false()] },
            Claim::Raw(v) => vec![Fr::from(*v)],
            Claim::HolderPk(pk) => encode_pk_to_field(pk),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub claims : BTreeMap<String, Claim>,
    pub signature: Signature23G1<Bls12_381>,
}

impl Credential {
    pub fn claims_json_str(&self) -> String {
        let map: serde_json::Map<String, serde_json::Value> = self.claims.iter().map(|(k, v)| {
            let encoded = match v {
                Claim::Bool(b) => serde_json::json!({"type": "bool", "val": b}),
                Claim::Value(s) => serde_json::json!({"type": "string", "val": s}),
                Claim::Raw(u) => serde_json::json!({"type": "raw", "val": u}),
                Claim::HolderPk(pk) => {
                    let mut pk_bytes = Vec::new();
                    pk.serialize_compressed(&mut pk_bytes).unwrap();
                    serde_json::json!({"type": "pk", "val": URL_SAFE_NO_PAD.encode(pk_bytes)})
                }
            };
            (k.clone(), encoded)
        }).collect();
        serde_json::to_string(&map).unwrap()
    }

    pub fn to_jwt(&self) -> String { // TODO: move to agever ?

        let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"BBS23-BLS12-381"}"#.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(self.claims_json_str().as_bytes());

        let mut sig_bytes = Vec::new();
        self.signature.serialize_compressed(&mut sig_bytes).unwrap();
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);

        format!("{}.{}.{}", header_b64, payload_b64, sig_b64)
    }

    pub fn from_jwt(jwt: &str) -> Result<Self, String> { // TODO: move to agever ?
        
        let parts: Vec<&str> = jwt.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err("invalid JWT: expected 3 dot-separated parts".into());
        }

        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])
            .map_err(|e| format!("payload base64 decode error: {e}"))?;
        let payload: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(&payload_bytes)
                .map_err(|e| format!("payload JSON parse error: {e}"))?;

        let mut claims = BTreeMap::new();
        for (key, obj) in payload {
            let typ = obj.get("type").and_then(|v| v.as_str())
                .ok_or_else(|| format!("claim '{key}' missing 'type'"))?;
            let val = obj.get("val")
                .ok_or_else(|| format!("claim '{key}' missing 'val'"))?;
            let claim = match typ {
                "bool" => Claim::Bool(val.as_bool()
                    .ok_or_else(|| format!("claim '{key}': expected bool val"))?),
                "string" => Claim::Value(val.as_str()
                    .ok_or_else(|| format!("claim '{key}': expected string val"))?
                    .to_string()),
                "raw" => Claim::Raw(val.as_u64()
                    .ok_or_else(|| format!("claim '{key}': expected u64 val"))?),
                "pk" => {
                    let pk_b64 = val.as_str()
                        .ok_or_else(|| format!("claim '{key}': expected string val for pk"))?;
                    let pk_bytes = URL_SAFE_NO_PAD.decode(pk_b64)
                        .map_err(|e| format!("claim '{key}': pk base64 decode error: {e}"))?;
                    let pk = SecP256Affine::deserialize_compressed(pk_bytes.as_slice())
                        .map_err(|e| format!("claim '{key}': pk deserialize error: {e}"))?;
                    Claim::HolderPk(pk)
                },
                other => return Err(format!("unknown claim type '{other}'")),
            };
            claims.insert(key, claim);
        }

        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2])
            .map_err(|e| format!("signature base64 decode error: {e}"))?;
        let signature = Signature23G1::deserialize_compressed(sig_bytes.as_slice())
            .map_err(|e| format!("signature deserialize error: {e}"))?;

        Ok(Credential { claims, signature })
    }
}

pub type IssuerKeyPair = KeypairG2<Bls12_381>;

pub type IssuerPublicKey = PublicKeyG2<Bls12_381>;

pub type HolderPublicKey = SecP256Affine;

pub type HolderSecretKey = SecP256Fr;

pub type Nonce = Vec<u8>;

 #[derive(Debug, Clone)]
pub struct HolderKeyPair {pub pk: SecP256Affine, pub sk: SecP256Fr}

impl HolderKeyPair {
    pub fn new_from_rng(rng: &mut StdRng) -> Self {
        let sk = SecP256Fr::rand(rng);
        let pk = (ecdsa::Signature::generator() * sk).into_affine();
        Self { pk, sk }
    }
}

/// The CRS for generating the base points of the BBS signature.
const SIG_LABEL: &[u8] = b"sig label";

/// The CRS for generating the base points of the commitment for the messages in the BBS signature.
const COMM_LABEL: &[u8] = b"comm label";

const BPP_LABEL: &[u8] = b"bpp label";

const COMM_LABEL_P256: &[u8] = b"comm label p256";
const COMM_LABEL_TOM256: &[u8] = b"comm label tom256";

const BPP_BASE: u16 = 2;
const BPP_BITSIZE: u16 = 64;
const BPP_NUM_PROOFS: u32 = 2; // TODO: not sure why it has to be 2.
const HOLDER_PK_NUM_CHUNKS: usize = 4;
const HOLDER_PK_CHUNK_SIZE: usize = 64;

// equality proof parameters
const WITNESS_BIT_SIZE: usize = 64;
const CHALLENGE_BIT_SIZE: usize = 180;
const ABORT_PARAM: usize = 8;
const RESPONSE_BYTE_SIZE: usize = 32;
const NUM_REPETITIONS: usize = 1;

// correct ecdsa verif proof parameters
const NUM_REPS_SCALAR_MULT: usize = 128; 

type EqualProof = eq_across_groups::Proof<
    Tom256Affine,
    G1Affine,
    WITNESS_BIT_SIZE,
    CHALLENGE_BIT_SIZE,
    ABORT_PARAM,
    RESPONSE_BYTE_SIZE,
    NUM_REPETITIONS>;

type SigProver = PoKEcdsaSigCommittedPublicKeyProtocol<NUM_REPS_SCALAR_MULT>;
type SigProof = PoKEcdsaSigCommittedPublicKey<NUM_REPS_SCALAR_MULT>;

impl Params {

    /// Instantiates the parameters for the committed disclosure of messages in BBS signatures.
    /// The label is used to derive the public base points for the signature and the commitment, and the message count is the number of messages supported by the signature params.
    pub fn new(label: &[u8], schema: &Schema) -> Self {
        let message_count = schema.len() as u32; // TODO: check schema
        let sig_params = SignatureParams23G1::<Bls12_381>::new::<Sha256>([SIG_LABEL, label].concat().as_slice(), message_count);
        let comm_key = PedersenCommitmentKey::<G1Affine>::new::<Sha256>([COMM_LABEL, label].concat().as_slice());

        let bpp_params = BppSetupParams::<G1Affine>::new_for_perfect_range_proof::<Sha256>(BPP_LABEL, BPP_BASE, BPP_BITSIZE, BPP_NUM_PROOFS);

        let comm_key_p256 = PedersenCommitmentKey::<SecP256Affine>::new::<Sha256>([COMM_LABEL_P256, label].concat().as_slice());
        let comm_key_tom256 = PedersenCommitmentKey::<Tom256Affine>::new::<Sha256>([COMM_LABEL_TOM256, label].concat().as_slice());

        Self { sig_params, comm_key, bpp_params, comm_key_p256, comm_key_tom256, schema: schema.clone()}
    }

    pub fn header() -> Fr {
        hash_to_field::<Fr, Sha256>(b"", "<unused>>".as_bytes())
    }

    pub fn msg_bool(b: bool) -> Fr {
        if b { Self::msg_true() } else { Self::msg_false() }
    }

    pub fn msg_true() -> Fr {
        hash_to_field::<Fr, Sha256>(b"", "true".as_bytes())
    }

    pub fn msg_false() -> Fr {
        hash_to_field::<Fr, Sha256>(b"", "false".as_bytes())
    }

    /// Checks that the reveal and commit indices are valid (i.e., within bounds and disjoint).
    pub fn check_indices(&self, reveal_idx: &Scope, commit_idx: &Scope) -> Option<Error> {
        // TODO: clone ?
        for idx in reveal_idx.union(commit_idx) {
            if !self.schema.fields.contains_key(idx) {
                return Some(Error::InvalidMsgIdx(idx.clone()));
            }
        }
        if !reveal_idx.is_disjoint(&commit_idx) {
            return Some(Error::NonDisjointRevealAndCommitIndices);
        }
        None
    }

    pub fn com_key_vec(&self) -> Vec<G1Affine> {
        vec![self.comm_key.g, self.comm_key.h]
    }
}

impl Schema {

    pub fn new(version: u32, fields: Vec<(String, Range<usize>)>) -> Self {
        // checks that the ranges are valid and non-overlapping
        let mut used = BTreeSet::new();
        for (field, range) in fields.clone() {
            if range.start >= range.end {
                panic!("invalid range for field '{field}': start must be less than end");
            }
            for idx in range.clone() {
                if used.contains(&idx) {
                    panic!("overlapping ranges for field '{field}': index {idx} is already used by another field");
                }
                used.insert(idx);
            }
        }
        
        Self { version, fields: fields.into_iter().collect() }
    }

    pub fn get(&self, field: &String) -> Option<Range<usize>> {
        self.fields.get(field).cloned()
    }

    pub fn len(&self) -> usize {
        self.fields.iter().map(|(_, range)| range.len()).sum()
    }
}

pub struct Issuer {
    params: Params,
    issuer_keypair: IssuerKeyPair,
}

pub fn claims_to_messages(claims: &BTreeMap<String, Claim>, schema: &Schema) -> Result<Vec<Fr>, Error> {
    let mut messages = vec![Fr::zero(); schema.len()];
    for (field, claim) in claims {
        match schema.get(field) {
            None => return Err(Error::InvalidMsgIdx(field.clone())), // TODO: better error
            Some(idx) => {
                let msg_fields = claim.to_field();
                if msg_fields.len() != idx.len() {
                    return Err(Error::InvalidMsg(field.clone(), msg_fields.len(), idx.len())); // TODO: better error
                }
                for (msg_idx, msg_field) in idx.zip(msg_fields.into_iter()) {
                    messages[msg_idx] = msg_field;
                }
            },
        }
    }
    Ok(messages)
}

impl Issuer {

    pub fn new(params: &Params, issuer_keypair: IssuerKeyPair) -> Self {
        Self { params: params.clone(), issuer_keypair }
    }

    
    pub fn issue_credential<R: RngCore>(&self, rng: &mut R, claims: Vec<(String, Claim)>) -> Result<Credential, Error> {
        
        let messages = claims_to_messages(&claims.iter().cloned().collect(), &self.params.schema)?;

        // Sign the messages
        let sig = Signature23G1::new(
            rng, 
            &messages,
            &self.issuer_keypair.secret_key,
            &self.params.sig_params
        ).expect("signing failed");

        Ok(Credential { claims: claims.into_iter().collect(), signature: sig })
    }
}

impl CommittedDisclosurePresenter {

    /// Creates a new committed disclosure.
    pub fn new<R: RngCore>(
        rng: &mut R,
        params: &Params,
        cred: &Credential,
        reveal_id: Scope,
        commit_idx: Scope,
        context: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        
        if let Some(e) = params.check_indices(&reveal_id, &commit_idx) {
            return Err(e);
        }

        let mut revealed_msgs = IndexMap::new();
        for idx in reveal_id.iter() {
            let idxs = params.schema.get(idx).unwrap();
            let claim = cred.claims.get(idx).unwrap();
            let msg_fields = claim.to_field();
            for (msg_idx, msg_field) in idxs.zip(msg_fields.into_iter()) {
                revealed_msgs.insert(msg_idx, msg_field);
            }
        }

        let mut  committed_msgs = IndexMap::new();
        for idx in commit_idx.iter() {
            let idxs = params.schema.get(idx).unwrap();
            let claim = cred.claims.get(idx).unwrap();
            let msg_fields = claim.to_field();
            for (msg_idx, msg_field) in idxs.zip(msg_fields.into_iter()) {
                committed_msgs.insert(msg_idx, msg_field);
            }
        }

        // Create the committed values for the messages at the commit indices
        let opennings: IndexMap<Fr> = committed_msgs
            .iter()
            .map(|(idx, _)| (idx.clone(), Fr::rand(rng)))
            .collect();

        let committed: IndexMap<G1Affine> = committed_msgs
            .iter()
            .map(|(idx, msg)| {
                (idx.clone(), params.comm_key.commit(msg, &opennings[&idx]))
            })
            .collect();

        // builds a context string for the presentation
        let context_vec = get_context_string(context, &committed);

        Ok(Self {
            params: params.clone(),
            cred: cred.clone(),
            committed_com: committed,
            revealed: revealed_msgs,
            committed_opennings: opennings,
            committed_msgs: committed_msgs,
            context: context_vec,
        })
    }

    pub fn gen_base_proof<R: RngCore>(&self, rng: &mut R) -> CommittedDisclosure {
        let statements = CommittedDisclosureStatement::new(&self.params, &self.revealed, &self.committed_com, None);
        let prover_proof_spec = ProofSpec::new(
            statements.statements.clone(),
            statements.equalities.clone(),
            vec![],
            Some(self.context.clone()),
        );
        prover_proof_spec.validate().unwrap();

        let witness = CommittedDisclosureWitness::new(&self.cred.signature.clone(), self.committed_msgs.clone(), self.committed_opennings.clone());

        let (proof, _) = Proof::new::<R, Sha256>(
            rng,
            prover_proof_spec.clone(),
            witness.0,
            None,
            Default::default(),
        )
        .unwrap();
        CommittedDisclosure { proof, commitments: self.committed_com.clone() }
    }

    pub fn gen_validity_proof<R: RngCore>(&self, rng: &mut R, today: u64) -> ProofOfValidty {

        let nbf_idxs = self.params.schema.get(&String::from("nbf")).expect("nbf not found in schema");
        let exp_idxs = self.params.schema.get(&String::from("exp")).expect("exp not found in schema");

        // claims should be single-messages
        if nbf_idxs.len() != 1 || exp_idxs.len() != 1 {
            panic!("nbf and exp claims should be single-message claims");
        }

        let nbf_idx = nbf_idxs.start;
        let exp_idx = exp_idxs.start;
        

        let statement = ValidityStatement::new(&self.params, 
            & self.committed_com[&nbf_idx], 
            &self.committed_com[&exp_idx], 
            today);
        
        let witness = ValidityWitness::new(self.committed_msgs[&nbf_idx], self.committed_opennings[&nbf_idx], self.committed_msgs[&exp_idx], self.committed_opennings[&exp_idx]);

        let proof_spec = ProofSpec::new(statement.statements.clone(), statement.equalities.clone(), vec![], None);
        proof_spec.validate().unwrap();
        let validity_proof = Proof::new::<R, Sha256>(rng,
            proof_spec.clone(),
             witness.into(), 
             None, 
             Default::default())
             .unwrap().0;
        ProofOfValidty { proof: validity_proof }
    }

    pub fn gen_holder_binding_proof<R: RngCore>(&self, rng: &mut R, sig: &ecdsa::Signature, holder_pk: &HolderPublicKey, nonce: &Nonce) -> ProofOfPossession {
        let pk_chunks = encode_pk_to_field(holder_pk);

        // commits to the pk chunks on the tom256 curve
        let pk_ops_tom256 : Vec<Tom256Fr> = pk_chunks.iter().map(|_| Tom256Fr::rand(rng)).collect();
        let pk_comms_tom256: Vec<Tom256Affine> = pk_chunks.iter().zip(pk_ops_tom256.iter()).map(|(chunk, r)| {
            self.params.comm_key_tom256.commit(chunk, r)
        }).collect();

        // computes a single commitment on the tom256 curve; this is the same commitment that
        // would be obtained from combining the commitments to the pk chunks homomorphically.
        let (pk_ops_x_tom256, pk_ops_y_tom256) = pk_ops_tom256.split_at(HOLDER_PK_NUM_CHUNKS);
        let rec_base = (0.. HOLDER_PK_NUM_CHUNKS)
        .map(|i| {
            let mut base_pow = BigInteger256::one();
            base_pow.muln((HOLDER_PK_CHUNK_SIZE*i) as u32);
            Tom256Fr::from(base_pow)
        }).collect::<Vec<Tom256Fr>>();

        let pk_op_x_tom256 = pk_ops_x_tom256.iter().zip(rec_base.iter())
            .fold(Tom256Fr::from(0), |acc, (r, base)| acc + *r * base);
        let pk_op_y_tom256 = pk_ops_y_tom256.iter().zip(rec_base.iter())
            .fold(Tom256Fr::from(0), |acc, (r, base)| acc + *r * base);

        let pk_x = from_base_field_to_scalar_field::<SecP256Fq, Tom256Fr>(holder_pk.x().unwrap());
        let pk_y = from_base_field_to_scalar_field::<SecP256Fq, Tom256Fr>(holder_pk.y().unwrap());
        let pk_com_tom256 = PointCommitment{
            x: self.params.comm_key_tom256.commit(&pk_x, &pk_op_x_tom256),
            y: self.params.comm_key_tom256.commit(&pk_y, &pk_op_y_tom256),
        };

        let pk_comop_tom256 = PointCommitmentWithOpening{
            x: pk_x,
            r_x: pk_op_x_tom256,
            y: pk_y,
            r_y: pk_op_y_tom256,
            comm: pk_com_tom256,
        };

        // generate a proof that the committed pk chunks open to the same value as the committed disclosure
        let comm_key_g1 = self.params.comm_key_tom256;
        let comm_key_g2 = self.params.comm_key;
        //let mut proofs = Vec::new();

        let pk_idxs = self.params.schema.get(&"holder_pk".to_string()).expect("holder_pk not found in schema");

        let proofs = pk_idxs.zip(pk_chunks).zip(pk_ops_tom256).map( // TODO: these zips use an implicit ordering
            |((pk_field_idx, chunk), pk_op_tom256)| {
            let pk_op_cd = self.committed_opennings.get(&pk_field_idx).expect("opening not found in committed disclosure");
            EqualProof::new(
                rng,
                &chunk,
                pk_op_tom256,
                *pk_op_cd,
                &comm_key_g1,
                &comm_key_g2,
                &mut new_merlin_transcript(b"holder binding proof"), // TODO: probably need more in that transcript
            ).unwrap()
            }
        ).collect();


        // generate a proof of knowledge of a signature tht verifies under the holder pk.

        // converts the signature to a proof-friendy format (K, z)
        let nonce_digest = Sha256::digest(nonce);
        let nonce_scalar = SecP256Fr::from_be_bytes_mod_order(&nonce_digest);
        let transformed_sig = TransformedEcdsaSig::new(sig, nonce_scalar.clone(), *holder_pk).unwrap();
        let prover = SigProver::init(
            rng,
            transformed_sig,
            nonce_scalar,
            *holder_pk,
            pk_comop_tom256,
            &self.params.comm_key_p256,
            &self.params.comm_key_tom256).unwrap();

        let mut transcript = new_merlin_transcript(b"test");
        prover.challenge_contribution(&mut transcript).unwrap();
        let challenge  = transcript.challenge_scalar(b"test");
        let proof = prover.gen_proof(&challenge);
        
        ProofOfPossession {
            comms: pk_comms_tom256,
            eq_proofs: proofs,
            sig_proof: proof,
        }
    }

    pub fn gen_presentation<R: RngCore>(&self, rng: &mut R, today: u64, holder_pk: &HolderPublicKey, nonce: &Nonce, holder_sig: &ecdsa::Signature) -> Presentation {
        let committed_disclosure = self.gen_base_proof(rng);
        let validity_proof = self.gen_validity_proof(rng, today);
        let holder_binding_proof = self.gen_holder_binding_proof(rng, holder_sig, holder_pk, nonce);
        Presentation { committed_disclosure, validity_proof, holder_binding_proof }
    }


}

impl CommittedDisclosureVerifier {
    pub fn new(params: Params, pk: IssuerPublicKey) -> Self {
        Self { params, pk }
    }

    pub fn verify<R: RngCore>(&self, rng: &mut R, pres: &CommittedDisclosure, claims: &Vec<(String, Claim)>, context: Option<Vec<u8>>) -> Result<(), Error> { // TODO harmonise claim input type
        
        let mut revealed = IndexMap::new();
        for (id, claim ) in claims {
            let idxs = self.params.schema.get(&id).ok_or(Error::InvalidMsgIdx(id.clone()))?;
            for (idx, msg) in idxs.zip(claim.to_field()) {
                revealed.insert(idx, msg);
            }
        }
        
        let statements = CommittedDisclosureStatement::new(
            &self.params,
            &revealed,
            &pres.commitments,
            Some(self.pk.clone()),
        );
        let context_vec = get_context_string(context, &pres.commitments);
        let proof_spec = ProofSpec::new(
            statements.statements.clone(),
            statements.equalities.clone(),
            vec![],
            Some(context_vec),
        );
        proof_spec.validate().unwrap();

        pres.proof
            .clone()
            .verify::<R, Sha256>(rng, proof_spec, None, Default::default())
            .map_err(|e| Error::VerificationFailed(format!("verification failed: {:?}", e)))
    }

    pub fn verify_validity_proof<R: RngCore>(&self, rng: &mut R, validity_proof: &ProofOfValidty, commitments : &IndexMap<G1Affine>, today: u64) -> Result<(), Error> {

        let nbf_idxs = self.params.schema.get(&String::from("nbf")).expect("nbf not found in schema");
        let exp_idxs = self.params.schema.get(&String::from("exp")).expect("exp not found in schema");

        // claims should be single-messages
        if nbf_idxs.len() != 1 || exp_idxs.len() != 1 {
            panic!("nbf and exp claims should be single-message claims");
        }

        let nbf_idx = nbf_idxs.start;
        let exp_idx = exp_idxs.start;

        let validity_statement = ValidityStatement::new(&self.params,
            &commitments[&nbf_idx],
            &commitments[&exp_idx],
            today);
        let proof_spec = ProofSpec::new(validity_statement.statements.clone(), validity_statement.equalities.clone(), vec![], None);
        proof_spec.validate().unwrap();
        
        validity_proof.clone().proof
            .verify::<R, Sha256>(rng, proof_spec, None, Default::default())
            .map_err(|e| Error::VerificationFailed(format!("validity proof verification failed: {:?}", e)))
    }


    pub fn verify_holder_binding_proof<R: RngCore>(&self, rng: &mut R, commitments : &IndexMap<G1Affine>, nonce : &Nonce, pop: &ProofOfPossession) -> Result<(), Error> {
        
        let pk_idxs = self.params.schema.get(&"holder_pk".to_string()).expect("holder_pk not found in schema");

        // verifies the proof that the Tom256 commitments are well-formed verifies.
        for ((pk_field_idx, pk_com_pop_tom256), eq_proof) in pk_idxs.zip(pop.comms.iter()).zip(pop.clone().eq_proofs) {
            let pk_com_cd = commitments.get(&pk_field_idx).expect("commitment not found in committed disclosure");
            eq_proof.verify(
                    &pk_com_pop_tom256,
                    &pk_com_cd,
                    &self.params.comm_key_tom256,
                    &self.params.comm_key,
                    &mut new_merlin_transcript(b"holder binding proof"),
                ).unwrap();
        }

       // Compute the commitment to the pk on the tom256 curve from the committed disclosure
       let pk_comms_x_tom256 = &pop.comms[..HOLDER_PK_NUM_CHUNKS];
       let pk_comms_y_tom256 = &pop.comms[HOLDER_PK_NUM_CHUNKS..];
       
       let rec_base = (0.. HOLDER_PK_NUM_CHUNKS)
        .map(|i| {
            let mut base_pow = BigInteger256::one();
            base_pow.muln((HOLDER_PK_CHUNK_SIZE*i) as u32);
            Tom256Fr::from(base_pow)
        }).collect::<Vec<Tom256Fr>>();
        let rec_base_p = rec_base.as_slice();

        let pk_com_x_tom256 = Tom256Projective::msm(pk_comms_x_tom256, rec_base_p).unwrap();
        let pk_com_y_tom256 = Tom256Projective::msm(pk_comms_y_tom256, rec_base_p).unwrap();
        let pk_com_tom256 = PointCommitment{
            x: pk_com_x_tom256.into_affine(),
            y: pk_com_y_tom256.into_affine(),
        };

        // verifies the proof of knowledge of a signature that verifies under the committed pk.
        let mut transcript = new_merlin_transcript(b"test");
        pop.sig_proof.challenge_contribution( &mut transcript).unwrap();
        let challenge = transcript.challenge_scalar(b"test");
 
        let nonce_scalar = SecP256Fr::from_be_bytes_mod_order(&Sha256::digest(nonce));
        
        pop.sig_proof.verify_using_randomized_mult_checker(
            nonce_scalar,
            pk_com_tom256,
            &challenge,
            self.params.comm_key_p256,
            self.params.comm_key_tom256,
            &mut RandomizedMultChecker::new_using_rng(rng),
            &mut RandomizedMultChecker::new_using_rng(rng))
            .map_err(|e| Error::VerificationFailed(format!("signature proof verification failed: {:?}", e)))
    }

    pub fn verify_presentation<R: RngCore>(&self, rng: &mut R, pres: &Presentation, today: u64, nonce: &Nonce, claims: Vec<(String, Claim)>, ctx : Option<Vec<u8>>) -> Result<(), Error> {
        self.verify(rng, &pres.committed_disclosure, &claims, ctx)?;
        self.verify_validity_proof(rng, &pres.validity_proof, &pres.committed_disclosure.commitments, today)?;
        self.verify_holder_binding_proof(rng, &pres.committed_disclosure.commitments.clone(), nonce, &pres.holder_binding_proof)?;
        Ok(())
    }
}

pub fn get_context_string(context: Option<Vec<u8>>, committed: &IndexMap<G1Affine>) -> Vec<u8> {
        let mut context_vec = vec![];
        if let Some(c) = context {
            context_vec.extend_from_slice(&c);
        }
        for (idx, com) in committed.iter() {
            context_vec.extend_from_slice(format!("|{}:{}", idx, com).as_bytes());
        }
        context_vec
}

/// The statement for proving knowledge of a BBS signature on multiple messages, 
/// where some messages are revealed and some are committed to.
struct CommittedDisclosureStatement {
    statements: Statements<Bls12_381>,
    equalities: MetaStatements,
}

/// The witness for proving knowledge of a BBS signature on multiple messages, 
/// where some messages are revealed and some are committed to.
struct CommittedDisclosureWitness(Witnesses<Bls12_381>);

impl CommittedDisclosureStatement {

    /// Creates a statement on the prover side.
    pub fn new(
        params: &Params,
        revealed_msgs: &IndexMap<Fr>,
        committed_msgs: &IndexMap<G1Affine>,
        public_key: Option<PublicKeyG2<Bls12_381>>,
    ) -> Self {
        let mut statements = Statements::new();
        if let Some(pk) = public_key {
            statements.add(PoKBBSSignature23G1Verifier::new_statement_from_params(
                params.sig_params.clone(),
                pk.clone(),
                (*revealed_msgs).clone(),
            ));
        } else {
        statements.add(PoKBBSSignature23G1Prover::new_statement_from_params(
            params.sig_params.clone(),
            (*revealed_msgs).clone(),
        ));
    }
        for (_, com) in committed_msgs.iter() {
            statements.add(PedersenCommitmentStmt::new_statement_from_params(
                vec![params.comm_key.g, params.comm_key.h],
                com.clone(),
            ));
        }

        let mut meta_statements = MetaStatements::new();
        for (stm, &idx) in committed_msgs.keys().enumerate() {
            meta_statements.add_witness_equality(EqualWitnesses(
                vec![
                    (0, idx),     // the idx-th message in the signature...
                    (stm + 1, 0), // ... is equal to the message in the stm-th commitment.
                ]
                .into_iter()
                .collect(),
            ));
        }

        Self {
            statements,
            equalities: meta_statements,
        }
    }
}


impl CommittedDisclosureWitness {

    /// Creates a new witness.
    pub fn new(
        sig: &Signature23G1<Bls12_381>,
        unrevealed_msgs: IndexMap<Fr>,
        opennings: IndexMap<Fr>,
    ) -> Self {
        let mut witness = Witnesses::new();
        witness.add(PoKBBSSignature23G1::new_as_witness(
            (*sig).clone(),
            unrevealed_msgs.clone(),
        ));
        for (idx, &m) in unrevealed_msgs.iter() {
            let r = opennings[idx];
            witness.add(Witness::PedersenCommitment(vec![m, r]));
        }
        Self(witness)
    }
}

/// The statement for proving the validity of the committed messages in the committed disclosure,
/// by proving that the committed messages satisfy the bound nbf < today < exp.
pub struct ValidityStatement {
    statements: Statements<Bls12_381>,
    equalities: MetaStatements,
}

/// The witness for proving the validity of the committed messages in the committed disclosure,
/// by proving that the committed messages satisfy the bound nbf < today < exp.
pub struct ValidityWitness {
    witness: Witnesses<Bls12_381>,
}

impl ValidityStatement {

    pub fn new(params : &Params, committed_nbf: &G1Affine, committed_exp: &G1Affine, today: u64) -> Self {

        // TODO: single proof for both bounds for now
        let mut validity_statement = Statements::<Bls12_381>::new();
        validity_statement.add(PedersenCommitmentStmt::new_statement_from_params(params.com_key_vec(), *committed_nbf));
        validity_statement.add(PedersenCommitmentStmt::new_statement_from_params(params.com_key_vec(), *committed_exp));
        validity_statement.add(BoundCheckStmt::new_statement_from_params(0, today+1, params.bpp_params.clone()).unwrap());
        validity_statement.add(BoundCheckStmt::new_statement_from_params(today, u64::MAX, params.bpp_params.clone()).unwrap());
        
        let mut meta_statements = MetaStatements::new();
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![
                (0, 0), // the 0-th witness in the first statement (the nbf)...
                (2, 0), // ... is equal to  the 0-th witness in the third statement (the value in the lower bound check for nbf).
            ]
            .into_iter()
            .collect(),
        ));
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![
                (1, 0), // the 0-th witness in the second statement (the exp)...
                (3, 0), // ... is equal to  the 0-th witness in the fourth statement (the value in the upper bound check for exp).
            ]
            .into_iter()
            .collect(),
        ));
        Self { statements: validity_statement, equalities: meta_statements}
    }
}

impl ValidityWitness {
    pub fn new(nbf_msg: Fr, nbf_openning: Fr, exp_msg: Fr, exp_openning: Fr) -> Self {
        let mut witness = Witnesses::new();
        witness.add(Witness::PedersenCommitment(vec![nbf_msg, nbf_openning]));
        witness.add(Witness::PedersenCommitment(vec![exp_msg, exp_openning]));
        witness.add(Witness::BoundCheckBpp(nbf_msg));
        witness.add(Witness::BoundCheckBpp(exp_msg));
        Self { witness }  
    }
}

impl Into<Witnesses<Bls12_381>> for ValidityWitness {
    fn into(self) -> Witnesses<Bls12_381> {
        self.witness  
    }
}

fn encode_pk_to_field<F: PrimeField>(pk: &SecP256Affine) -> Vec<F> {
    let pk_x = pk.x().unwrap().into_bigint();
    let pk_y = pk.y().unwrap().into_bigint();
    let mut res = vec![];
    res.extend_from_slice(decompose_bigint(&pk_x, HOLDER_PK_CHUNK_SIZE).as_slice());
    res.extend_from_slice(decompose_bigint(&pk_y, HOLDER_PK_CHUNK_SIZE).as_slice());
    res
}

// Decomposes a scalar into chunks of the given bit size, and returns the chunks as field elements.
// Adapted from docknework's code.
// TODO: the version of ark_ff used by docknetwork does not provide arithmetic ops on BigInt. So this is quite clunky.
fn decompose_bigint<F: PrimeField, const N: usize>(n: &BigInt<N>, chunk_bit_size: usize) -> Vec<F> {
    let mut chunks = vec![];
    for bits in n.to_bits_le().chunks(chunk_bit_size) {
        let l = bits.len();
        let mut chunk = vec![0_u8; (l + 7) / 8];
        for (i, bits8) in bits.chunks(8).enumerate() {
            for (j, bit) in bits8.iter().enumerate() {
                chunk[i] |= (*bit as u8) << j;
            }
        }
        chunks.push(F::from_le_bytes_mod_order(&chunk));
    }
    chunks
}

#[cfg(test)]
mod tests {

    use ark_std::{start_timer, end_timer};

    use ark_std::rand::{SeedableRng, rngs::StdRng};

    use super::*;


    #[test]
    fn bbs_sign_and_verify_with_committed_msgs() {

        let schema_fields : Vec<(String, Range<usize>)> = vec![
            (String::from("header"), 0..1),
            (String::from("name"), 1..2),
            (String::from("above16"), 2..3),
            (String::from("above18"), 3..4),
            (String::from("nbf"), 4..5),
            (String::from("exp"), 5..6),
            (String::from("holder_pk"), 6..14),
        ];
        let schema = Schema::new(0, schema_fields);

        let mut rng = StdRng::seed_from_u64(0);
        let reveal_idx: Scope = Scope::from_iter(vec![String::from("above16"), String::from("above18")]);
        let commit_idx: Scope = Scope::from_iter(vec![String::from("header"), String::from("name"), String::from("nbf"), String::from("exp"), String::from("holder_pk")]); 

        //// SETUP
        let params = Params::new(b"test", &schema);

        //// KEYGEN
        // Generate a signer keypair from the params
        let issuer_keypair = KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(
            &mut rng,
            &params.sig_params,
        );

        let ecdsa_keypair = HolderKeyPair::new_from_rng(&mut rng);

        // cred is valid right away
        let nbf = chrono::Utc::now().timestamp() as u64 - 60 ; // For demo: avoid clock skew issue with holder by issuing credential with nbf in the past
        // and expires in 1 month:
        let exp = (chrono::Utc::now() + chrono::Duration::days(30)).timestamp() as u64;

        let name = "Roger".to_string();
        let age = 20;

        let claims = vec![
            ("header".to_string(), Claim::Value("<unused>".to_string())),
            ("name".to_string(), Claim::Value(name)),
            ("above16".to_string(), Claim::Bool(age >= 16)),
            ("above18".to_string(), Claim::Bool(age >= 18)),
            ("nbf".to_string(), Claim::Raw(nbf)),
            ("exp".to_string(), Claim::Raw(exp)),
            ("holder_pk".to_string(), Claim::HolderPk(ecdsa_keypair.pk)),
        ];

        let revealed_claims : Vec<(String, Claim)> = claims.clone().into_iter().filter(|(id, _)| reveal_idx.contains(id)).collect();


        //// ISSUANCE
        let issuer = Issuer::new(&params, issuer_keypair.clone());
        let cred = issuer.issue_credential(&mut rng, claims).expect("credential issuance failed");


        println!("Credential JWT: {}", cred.to_jwt());
        println!("Claims in the credential: {}", cred.claims_json_str());

        let cred = Credential::from_jwt(&cred.to_jwt()).unwrap();

        //// PRESENTATION
        let ctx = None; //Some("test context".as_bytes().to_vec());
        let today = (chrono::Utc::now() + chrono::Duration::seconds(30)).timestamp() as u64;
        let presenter = CommittedDisclosurePresenter::new(
            &mut rng,
            &params,
            &cred,
            reveal_idx.clone(),
            commit_idx.clone(),
            ctx.clone()

        )
        .expect("committed disclosure failed");

        let start_base = start_timer!(|| "base proof generation");
        let pres_base = presenter.gen_base_proof(&mut rng);
        end_timer!(start_base);

        let start_validity = start_timer!(|| "validity proof generation");
        let pres_validity = presenter.gen_validity_proof(&mut rng, today);
        end_timer!(start_validity);

        let nonce = "test nonce".as_bytes().to_vec();

        let nonce_scalar = SecP256Fr::from_be_bytes_mod_order(&Sha256::digest(&nonce));

        let ecdsa_sig = ecdsa::Signature::new_prehashed(&mut rng, nonce_scalar, ecdsa_keypair.sk);
        
        let start_holder_binding = start_timer!(|| "holder binding proof generation");
        let holder_binding_proof = presenter.gen_holder_binding_proof(
            &mut rng,
            &ecdsa_sig,
            &ecdsa_keypair.pk,
            &nonce,
        );
        end_timer!(start_holder_binding);

        // TRANSMISSION
        let pres = Presentation { committed_disclosure: pres_base.clone(), validity_proof: pres_validity.clone(), holder_binding_proof: holder_binding_proof.clone() };
        let mut temp_buf = vec![0u8; pres.serialized_size(ark_serialize::Compress::Yes)];
        pres.serialize_compressed(&mut temp_buf[..]).unwrap();
        let pres_r = Presentation::deserialize_compressed(&temp_buf[..]).unwrap();
        let Presentation { committed_disclosure: pres_base_r, validity_proof: pres_validity_r, holder_binding_proof: holder_binding_proof_r } = pres_r;
        
        // VERIFICATION
        let start_verification = start_timer!(|| "total proof verification");
        let verifier = CommittedDisclosureVerifier::new(
            params.clone(),
            issuer_keypair.public_key.clone());

        let start_base_verification = start_timer!(|| "base proof verification");
        verifier.verify(&mut rng, &pres_base_r, &revealed_claims, ctx.clone()).expect("base verification of presentation failed");
        end_timer!(start_base_verification);

        let start_validity_verification = start_timer!(|| "validity proof verification");
        verifier.verify_validity_proof(&mut rng, &pres_validity_r, &pres_base_r.commitments, today).expect("verification of validity proof failed");
        end_timer!(start_validity_verification);

        let start_holder_binding_verification = start_timer!(|| "holder binding proof verification");
        verifier.verify_holder_binding_proof(&mut rng, &pres_base_r.commitments, &nonce, &holder_binding_proof_r).expect("verification of holder binding proof failed");
        end_timer!(start_holder_binding_verification);
        end_timer!(start_verification);


        // SIZES
        println!("Base proof size: {} bytes", pres_base.serialized_size(ark_serialize::Compress::Yes));
        println!("Validity proof size: {} bytes", pres_validity.serialized_size(ark_serialize::Compress::Yes));
        println!("Holder binding proof size: {} bytes", holder_binding_proof.sig_proof.serialized_size(ark_serialize::Compress::Yes));
        println!("Full Presentation size: {} bytes", pres.serialized_size(ark_serialize::Compress::Yes));

    }
}
