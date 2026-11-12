//! Signet's MLS operations on OpenMLS, with no binding-specific types, so the same core can back the
//! Node addon today and Swift (via UniFFI) later.
//!
//! State is functional: every call takes the client's serialized key store and returns the new one.
//! The caller persists it. A call that fails, or a commit that hasn't been approved, leaves the
//! caller's copy untouched, which is what lets Signet check credentials against identity logs
//! before applying anything.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{random::OpenMlsRand, OpenMlsProvider};

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Pad every encrypted message to a multiple of this many bytes so sizes leak less.
pub const PADDING: usize = 256;

pub type Result<T> = std::result::Result<T, String>;

macro_rules! fail {
    ($context:expr) => {
        |error| format!("{}: {:?}", $context, error)
    };
}

/// A group member as Signet sees it: the leaf, its credential identity and its signature key.
#[derive(Debug, Clone)]
pub struct MemberInfo {
    pub leaf_index: u32,
    pub identity: Vec<u8>,
    pub signature_key: Vec<u8>,
}

pub struct Signed<'a> {
    pub identity: &'a [u8],
    pub private_key: &'a [u8],
    pub public_key: &'a [u8],
}

impl Signed<'_> {
    fn signer(&self) -> SignatureKeyPair {
        SignatureKeyPair::from_raw(SignatureScheme::ED25519, self.private_key.to_vec(), self.public_key.to_vec())
    }

    fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.identity.to_vec()).into(),
            signature_key: self.public_key.to_vec().into(),
        }
    }
}

pub struct KeyPackageOut {
    pub state: String,
    pub key_package: String,
}

pub struct GroupOut {
    pub state: String,
    pub group_id: String,
    pub welcome: Option<String>,
}

pub struct CommitOut {
    pub state: String,
    pub commit: String,
    pub welcome: Option<String>,
}

pub struct JoinOut {
    pub state: String,
    pub group_id: String,
    pub members: Vec<MemberInfo>,
}

pub enum Incoming {
    Application {
        state: String,
        sender: MemberInfo,
        plaintext: Vec<u8>,
    },
    Commit {
        /// The new state if the commit was applied; the old state otherwise.
        state: String,
        sender: MemberInfo,
        added: Vec<MemberInfo>,
        removed: Vec<u32>,
        self_removed: bool,
        applied: bool,
    },
}

fn provider(state: &str) -> Result<OpenMlsRustCrypto> {
    let provider = OpenMlsRustCrypto::default();
    if !state.is_empty() {
        let entries: BTreeMap<String, String> = serde_json::from_str(state).map_err(fail!("state is not valid"))?;
        let mut values = provider.storage().values.write().map_err(fail!("storage lock"))?;
        for (key, value) in entries {
            values.insert(B64.decode(key).map_err(fail!("state key"))?, B64.decode(value).map_err(fail!("state value"))?);
        }
    }
    Ok(provider)
}

fn save(provider: &OpenMlsRustCrypto) -> Result<String> {
    let values = provider.storage().values.read().map_err(fail!("storage lock"))?;
    let entries: BTreeMap<String, String> = values.iter().map(|(k, v)| (B64.encode(k), B64.encode(v))).collect();
    serde_json::to_string(&entries).map_err(fail!("serialize state"))
}

fn decode(data: &str) -> Result<Vec<u8>> {
    B64.decode(data).map_err(fail!("not base64url"))
}

fn message_body(data: &str) -> Result<MlsMessageBodyIn> {
    let bytes = decode(data)?;
    Ok(MlsMessageIn::tls_deserialize_exact(&mut bytes.as_slice()).map_err(fail!("not an MLS message"))?.extract())
}

fn encode_out(message: &MlsMessageOut) -> Result<String> {
    Ok(B64.encode(message.to_bytes().map_err(fail!("serialize message"))?))
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .padding_size(PADDING)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build()
}

fn load(provider: &OpenMlsRustCrypto, group_id: &str) -> Result<MlsGroup> {
    MlsGroup::load(provider.storage(), &GroupId::from_slice(&decode(group_id)?))
        .map_err(fail!("load group"))?
        .ok_or_else(|| "no such group in this state".to_string())
}

fn member_info(member: Member) -> MemberInfo {
    MemberInfo {
        leaf_index: member.index.u32(),
        identity: member.credential.serialized_content().to_vec(),
        signature_key: member.signature_key,
    }
}

fn leaf_info(leaf_index: u32, leaf: &LeafNode) -> MemberInfo {
    MemberInfo {
        leaf_index,
        identity: leaf.credential().serialized_content().to_vec(),
        signature_key: leaf.signature_key().as_slice().to_vec(),
    }
}

/// A fresh key package for this client. Its private keys go into the returned state. A last-resort
/// key package can be used more than once, so draining a client's packages can't lock it out.
pub fn key_package(state: &str, me: &Signed, last_resort: bool) -> Result<KeyPackageOut> {
    let provider = provider(state)?;
    // Every key package declares support for the last-resort extension, so either kind validates.
    let capabilities = Capabilities::new(None, None, Some(&[ExtensionType::LastResort]), None, None);
    let builder = KeyPackage::builder().leaf_node_capabilities(capabilities);
    let builder = if last_resort { builder.mark_as_last_resort() } else { builder };
    let bundle = builder
        .build(CIPHERSUITE, &provider, &me.signer(), me.credential())
        .map_err(fail!("build key package"))?;
    let bytes = bundle.key_package().tls_serialize_detached().map_err(fail!("serialize key package"))?;
    Ok(KeyPackageOut { state: save(&provider)?, key_package: B64.encode(bytes) })
}

fn validate_key_package(data: &str, crypto: &impl openmls_traits::crypto::OpenMlsCrypto) -> Result<KeyPackage> {
    let bytes = decode(data)?;
    let key_package = KeyPackageIn::tls_deserialize_exact(&mut bytes.as_slice())
        .map_err(fail!("not a key package"))?
        .validate(crypto, ProtocolVersion::Mls10)
        .map_err(fail!("invalid key package"))?;
    if key_package.ciphersuite() != CIPHERSUITE {
        return Err(format!("key package uses {:?}", key_package.ciphersuite()));
    }
    Ok(key_package)
}

/// Check a key package's own signature and suite, and say whose it claims to be.
pub fn inspect_key_package(data: &str) -> Result<MemberInfo> {
    let provider = OpenMlsRustCrypto::default();
    let key_package = validate_key_package(data, provider.crypto())?;
    Ok(leaf_info(0, key_package.leaf_node()))
}

/// Create a group and add these key packages in one commit.
pub fn create_group(state: &str, me: &Signed, key_packages: &[String]) -> Result<GroupOut> {
    let provider = provider(state)?;
    let signer = me.signer();
    let group_id = provider.rand().random_vec(16).map_err(fail!("random group id"))?;
    let mut group = MlsGroup::builder()
        .with_group_id(GroupId::from_slice(&group_id))
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .padding_size(PADDING)
        .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build(&provider, &signer, me.credential())
        .map_err(fail!("create group"))?;
    let mut welcome = None;
    if !key_packages.is_empty() {
        let packages = key_packages
            .iter()
            .map(|data| validate_key_package(data, provider.crypto()))
            .collect::<Result<Vec<_>>>()?;
        let (_, message, _) = group.add_members(&provider, &signer, &packages).map_err(fail!("add members"))?;
        group.merge_pending_commit(&provider).map_err(fail!("merge commit"))?;
        welcome = Some(encode_out(&message)?);
    }
    Ok(GroupOut { state: save(&provider)?, group_id: B64.encode(group_id), welcome })
}

/// One commit that removes these leaves and adds these key packages. Applied locally at once.
pub fn commit(state: &str, group_id: &str, me: &Signed, remove: &[u32], add: &[String]) -> Result<CommitOut> {
    let provider = provider(state)?;
    let signer = me.signer();
    let mut group = load(&provider, group_id)?;
    let packages = add.iter().map(|data| validate_key_package(data, provider.crypto())).collect::<Result<Vec<_>>>()?;
    let bundle = group
        .commit_builder()
        .propose_removals(remove.iter().map(|&leaf| LeafNodeIndex::new(leaf)))
        .propose_adds(packages)
        .load_psks(provider.storage())
        .map_err(fail!("load psks"))?
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .map_err(fail!("build commit"))?
        .stage_commit(&provider)
        .map_err(fail!("stage commit"))?;
    let (commit, welcome, _) = bundle.into_messages();
    group.merge_pending_commit(&provider).map_err(fail!("merge commit"))?;
    Ok(CommitOut {
        state: save(&provider)?,
        commit: encode_out(&commit)?,
        welcome: welcome.as_ref().map(encode_out).transpose()?,
    })
}

fn staged_welcome(provider: &OpenMlsRustCrypto, welcome: &str) -> Result<StagedWelcome> {
    let MlsMessageBodyIn::Welcome(welcome) = message_body(welcome)? else {
        return Err("expected a welcome".into());
    };
    StagedWelcome::new_from_welcome(provider, &join_config(), welcome, None).map_err(fail!("stage welcome"))
}

/// Decrypt a welcome and list the members it would join, without joining.
pub fn peek_welcome(state: &str, welcome: &str) -> Result<(String, Vec<MemberInfo>)> {
    let provider = provider(state)?;
    let staged = staged_welcome(&provider, welcome)?;
    let group_id = B64.encode(staged.group_context().group_id().as_slice());
    Ok((group_id, staged.members().map(member_info).collect()))
}

pub fn join_group(state: &str, welcome: &str) -> Result<JoinOut> {
    let provider = provider(state)?;
    let group = staged_welcome(&provider, welcome)?.into_group(&provider).map_err(fail!("join group"))?;
    Ok(JoinOut {
        state: save(&provider)?,
        group_id: B64.encode(group.group_id().as_slice()),
        members: group.members().map(member_info).collect(),
    })
}

pub fn encrypt(state: &str, group_id: &str, me: &Signed, plaintext: &[u8]) -> Result<(String, String)> {
    let provider = provider(state)?;
    let mut group = load(&provider, group_id)?;
    let message = group.create_message(&provider, &me.signer(), plaintext).map_err(fail!("encrypt"))?;
    Ok((save(&provider)?, encode_out(&message)?))
}

/// Decrypt an application message, or stage a commit and report what it changes. A commit is merged
/// only when `apply` is true, so the caller can check every credential first and call again.
pub fn process(state: &str, group_id: &str, data: &str, apply: bool) -> Result<Incoming> {
    let provider = provider(state)?;
    let mut group = load(&provider, group_id)?;
    let protocol: ProtocolMessage = match message_body(data)? {
        MlsMessageBodyIn::PrivateMessage(message) => message.into(),
        MlsMessageBodyIn::PublicMessage(message) => message.into(),
        _ => return Err("expected a group message".into()),
    };
    if protocol.group_id().as_slice() != decode(group_id)?.as_slice() {
        return Err("message is for another group".into());
    }
    let processed = group.process_message(&provider, protocol).map_err(fail!("process message"))?;
    let Sender::Member(leaf) = processed.sender().clone() else {
        return Err("message is not from a group member".into());
    };
    let sender = MemberInfo {
        leaf_index: leaf.u32(),
        identity: processed.credential().serialized_content().to_vec(),
        signature_key: group
            .members()
            .find(|member| member.index == leaf)
            .map(|member| member.signature_key)
            .unwrap_or_default(),
    };
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => {
            Ok(Incoming::Application { state: save(&provider)?, sender, plaintext: message.into_bytes() })
        }
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            let added = staged
                .add_proposals()
                .map(|proposal| leaf_info(u32::MAX, proposal.add_proposal().key_package().leaf_node()))
                .collect();
            let removed = staged.remove_proposals().map(|proposal| proposal.remove_proposal().removed().u32()).collect();
            let self_removed = staged.self_removed();
            let next = if apply {
                group.merge_staged_commit(&provider, *staged).map_err(fail!("merge commit"))?;
                save(&provider)?
            } else {
                state.to_string()
            };
            Ok(Incoming::Commit { state: next, sender, added, removed, self_removed, applied: apply })
        }
        _ => Err("standalone proposals are not used in Signet".into()),
    }
}

pub fn members(state: &str, group_id: &str) -> Result<Vec<MemberInfo>> {
    let provider = provider(state)?;
    Ok(load(&provider, group_id)?.members().map(member_info).collect())
}

pub fn epoch(state: &str, group_id: &str) -> Result<u64> {
    let provider = provider(state)?;
    Ok(load(&provider, group_id)?.epoch().as_u64())
}

pub fn is_active(state: &str, group_id: &str) -> Result<bool> {
    let provider = provider(state)?;
    Ok(load(&provider, group_id)?.is_active())
}

/// RFC 9420 exporter: a secret every current member derives and nobody else can.
pub fn export_secret(state: &str, group_id: &str, label: &str, length: usize) -> Result<String> {
    let provider = provider(state)?;
    let group = load(&provider, group_id)?;
    let secret = group.export_secret(provider.crypto(), label, &[], length).map_err(fail!("export secret"))?;
    Ok(B64.encode(secret))
}
