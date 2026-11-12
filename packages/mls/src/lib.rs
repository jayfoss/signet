//! Node bindings for Signet's MLS core. Bytes cross the boundary as base64url strings; every function
//! takes the client's serialized state and returns the new one.

pub mod core;
pub mod vrf;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use napi::{Error, Result};
use napi_derive::napi;

use crate::core::{Incoming, MemberInfo, Signed};

fn js<T>(result: core::Result<T>) -> Result<T> {
    result.map_err(Error::from_reason)
}

fn bytes(data: &str) -> Result<Vec<u8>> {
    B64.decode(data).map_err(|error| Error::from_reason(format!("not base64url: {error}")))
}

#[napi(object)]
pub struct Me {
    pub identity: String,
    pub private_key: String,
    pub public_key: String,
}

#[napi(object)]
pub struct Member {
    pub leaf_index: u32,
    pub identity: String,
    pub signature_key: String,
}

impl From<MemberInfo> for Member {
    fn from(info: MemberInfo) -> Self {
        Member {
            leaf_index: info.leaf_index,
            identity: B64.encode(info.identity),
            signature_key: B64.encode(info.signature_key),
        }
    }
}

#[napi(object)]
pub struct KeyPackageResult {
    pub state: String,
    pub key_package: String,
}

#[napi(object)]
pub struct GroupResult {
    pub state: String,
    pub group_id: String,
    pub welcome: Option<String>,
}

#[napi(object)]
pub struct CommitResult {
    pub state: String,
    pub commit: String,
    pub welcome: Option<String>,
}

#[napi(object)]
pub struct JoinResult {
    pub state: String,
    pub group_id: String,
    pub members: Vec<Member>,
}

#[napi(object)]
pub struct WelcomePreview {
    pub group_id: String,
    pub members: Vec<Member>,
}

#[napi(object)]
pub struct EncryptResult {
    pub state: String,
    pub message: String,
}

#[napi(object)]
pub struct ProcessResult {
    pub kind: String,
    pub state: String,
    pub sender: Member,
    pub plaintext: Option<String>,
    pub added: Vec<Member>,
    pub removed: Vec<u32>,
    pub self_removed: bool,
    pub applied: bool,
}

struct Keys {
    identity: Vec<u8>,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl Keys {
    fn from(me: &Me) -> Result<Self> {
        Ok(Keys { identity: bytes(&me.identity)?, private_key: bytes(&me.private_key)?, public_key: bytes(&me.public_key)? })
    }

    fn signed(&self) -> Signed<'_> {
        Signed { identity: &self.identity, private_key: &self.private_key, public_key: &self.public_key }
    }
}

#[napi]
pub fn key_package(state: String, me: Me, last_resort: bool) -> Result<KeyPackageResult> {
    let keys = Keys::from(&me)?;
    let out = js(core::key_package(&state, &keys.signed(), last_resort))?;
    Ok(KeyPackageResult { state: out.state, key_package: out.key_package })
}

#[napi]
pub fn inspect_key_package(key_package: String) -> Result<Member> {
    Ok(js(core::inspect_key_package(&key_package))?.into())
}

#[napi]
pub fn create_group(state: String, me: Me, key_packages: Vec<String>) -> Result<GroupResult> {
    let keys = Keys::from(&me)?;
    let out = js(core::create_group(&state, &keys.signed(), &key_packages))?;
    Ok(GroupResult { state: out.state, group_id: out.group_id, welcome: out.welcome })
}

#[napi]
pub fn commit(state: String, group_id: String, me: Me, remove: Vec<u32>, add: Vec<String>) -> Result<CommitResult> {
    let keys = Keys::from(&me)?;
    let out = js(core::commit(&state, &group_id, &keys.signed(), &remove, &add))?;
    Ok(CommitResult { state: out.state, commit: out.commit, welcome: out.welcome })
}

#[napi]
pub fn peek_welcome(state: String, welcome: String) -> Result<WelcomePreview> {
    let (group_id, members) = js(core::peek_welcome(&state, &welcome))?;
    Ok(WelcomePreview { group_id, members: members.into_iter().map(Member::from).collect() })
}

#[napi]
pub fn join_group(state: String, welcome: String) -> Result<JoinResult> {
    let out = js(core::join_group(&state, &welcome))?;
    Ok(JoinResult { state: out.state, group_id: out.group_id, members: out.members.into_iter().map(Member::from).collect() })
}

#[napi]
pub fn encrypt(state: String, group_id: String, me: Me, plaintext: String) -> Result<EncryptResult> {
    let keys = Keys::from(&me)?;
    let (state, message) = js(core::encrypt(&state, &group_id, &keys.signed(), &bytes(&plaintext)?))?;
    Ok(EncryptResult { state, message })
}

#[napi]
pub fn process(state: String, group_id: String, message: String, apply: bool) -> Result<ProcessResult> {
    Ok(match js(core::process(&state, &group_id, &message, apply))? {
        Incoming::Application { state, sender, plaintext } => ProcessResult {
            kind: "application".into(),
            state,
            sender: sender.into(),
            plaintext: Some(B64.encode(plaintext)),
            added: vec![],
            removed: vec![],
            self_removed: false,
            applied: true,
        },
        Incoming::Commit { state, sender, added, removed, self_removed, applied } => ProcessResult {
            kind: "commit".into(),
            state,
            sender: sender.into(),
            plaintext: None,
            added: added.into_iter().map(Member::from).collect(),
            removed,
            self_removed,
            applied,
        },
    })
}

#[napi]
pub fn members(state: String, group_id: String) -> Result<Vec<Member>> {
    Ok(js(core::members(&state, &group_id))?.into_iter().map(Member::from).collect())
}

#[napi]
pub fn epoch(state: String, group_id: String) -> Result<i64> {
    Ok(js(core::epoch(&state, &group_id))? as i64)
}

#[napi]
pub fn is_active(state: String, group_id: String) -> Result<bool> {
    js(core::is_active(&state, &group_id))
}

#[napi]
pub fn export_secret(state: String, group_id: String, label: String, length: u32) -> Result<String> {
    js(core::export_secret(&state, &group_id, &label, length as usize))
}

#[napi(object)]
pub struct VrfKeyPair {
    pub secret: String,
    pub public: String,
}

#[napi(object)]
pub struct VrfProof {
    pub proof: String,
    pub output: String,
}

fn key32(data: &str) -> Result<[u8; 32]> {
    bytes(data)?.try_into().map_err(|_| Error::from_reason("expected 32 bytes"))
}

#[napi]
pub fn vrf_keygen() -> VrfKeyPair {
    let key = vrf::keygen();
    VrfKeyPair { secret: B64.encode(key.secret), public: B64.encode(key.public) }
}

#[napi]
pub fn vrf_prove(secret: String, alpha: String) -> Result<VrfProof> {
    let (proof, output) = js(vrf::prove(&key32(&secret)?, &bytes(&alpha)?))?;
    Ok(VrfProof { proof: B64.encode(proof), output: B64.encode(output) })
}

#[napi]
pub fn vrf_verify(public: String, alpha: String, proof: String) -> Result<String> {
    Ok(B64.encode(js(vrf::verify(&key32(&public)?, &bytes(&alpha)?, &bytes(&proof)?))?))
}

/**
 * One side of a SPAKE2 exchange (Ed25519 group, the `spake2` crate's construction) for pairing a new
 * client over a short code. Side "a" is the account owner's device, side "b" the new client. Both derive
 * the same key only if they typed the same code; a wrong code gives different keys, which the first
 * message sealed under them exposes. The state can't be serialized: finish it in the same process.
 */
#[napi]
pub struct Pake {
    state: Option<spake2::Spake2<spake2::Ed25519Group>>,
    outbound: String,
}

#[napi]
impl Pake {
    #[napi(constructor)]
    pub fn new(side: String, password: String, id_a: String, id_b: String) -> Result<Self> {
        let password = spake2::Password::new(password.as_bytes());
        let (a, b) = (spake2::Identity::new(id_a.as_bytes()), spake2::Identity::new(id_b.as_bytes()));
        let (state, message) = match side.as_str() {
            "a" => spake2::Spake2::<spake2::Ed25519Group>::start_a(&password, &a, &b),
            "b" => spake2::Spake2::<spake2::Ed25519Group>::start_b(&password, &a, &b),
            _ => return Err(Error::from_reason("side must be \"a\" or \"b\"")),
        };
        Ok(Pake { state: Some(state), outbound: B64.encode(message) })
    }

    /// The message to send to the other side.
    #[napi(getter)]
    pub fn message(&self) -> String {
        self.outbound.clone()
    }

    /// The shared key (base64url), from the other side's message. Usable once.
    #[napi]
    pub fn finish(&mut self, inbound: String) -> Result<String> {
        let state = self.state.take().ok_or_else(|| Error::from_reason("this exchange is already finished"))?;
        let key = state.finish(&bytes(&inbound)?).map_err(|error| Error::from_reason(format!("pairing failed: {error:?}")))?;
        Ok(B64.encode(key))
    }
}
