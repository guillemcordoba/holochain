//! Collection of cells to form a holochain application
use crate::{dna::JsonProperties, prelude::{DnaDefHashed, DnaFile, wasm}};
use derive_more::Into;
use holo_hash::AgentPubKey;
use holochain_serialized_bytes::SerializedBytes;
use holochain_zome_types::cell::CellId;
use std::{collections::BTreeMap, path::PathBuf};

/// Placeholder used to identify installed apps
pub type InstalledAppId = String;

/// A friendly (nick)name used by UIs to refer to the Cells which make up the app
pub type CellNick = String;

/// A collection of [DnaHash]es paired with an [AgentPubKey] and an app id
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InstallAppPayload {
    /// Placeholder to find the installed app
    pub installed_app_id: InstalledAppId,
    /// The agent that installed this app
    pub agent_key: AgentPubKey,
    /// The Dna paths in this app
    pub dnas: Vec<InstallAppDnaPayload>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum InstallAppDnaPayload {
    InstallAppDnaPayloadPath(InstallAppDnaPayloadPath),
    InstallAppDnaPayloadFile(InstallAppDnaPayloadFile),
}

/// Information needed to specify a Dna as part of an App
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InstallAppDnaPayloadPath {
    /// The path of the DnaFile
    pub path: PathBuf,
    /// The CellNick which will be assigned to this Dna when installed
    pub nick: CellNick,
    /// Properties to override when installing this Dna
    pub properties: Option<JsonProperties>,
    /// App-specific proof-of-membrane-membership, if required by this app
    pub membrane_proof: Option<MembraneProof>,
}

/// Wasms need to be an ordered map from WasmHash to a wasm::DnaWasm
pub type WasmsInput = Vec<(holo_hash::WasmHash, wasm::DnaWasm)>;

/// Represents a full DNA file including WebAssembly bytecode.
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
pub struct DnaFileInput {
    /// The hashable portion that can be shared with hApp code.
    pub dna: DnaDefHashed,

    /// The bytes of the WASM zomes referenced in the Dna portion.
    pub code: WasmsInput,
}

/// Information needed to specify a Dna as part of an App
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InstallAppDnaPayloadFile {
    /// The path of the DnaFile
    pub file: DnaFileInput,
    /// The CellNick which will be assigned to this Dna when installed
    pub nick: CellNick,
    /// App-specific proof-of-membrane-membership, if required by this app
    pub membrane_proof: Option<MembraneProof>,
}

impl Into<DnaFile> for DnaFileInput {
    fn into(self) -> DnaFile {
        let mut code: BTreeMap<holo_hash::WasmHash, wasm::DnaWasm> = BTreeMap::new();

        for c in self.code {
            code.insert(c.0, c.1);
        }

        DnaFile {
            code,
            dna: self.dna,
        }
    }
}

impl InstallAppDnaPayload {
    /// Create a payload with no JsonProperties or MembraneProof. Good for tests.
    pub fn path_only(path: PathBuf, nick: CellNick) -> Self {
        InstallAppDnaPayload::InstallAppDnaPayloadPath(InstallAppDnaPayloadPath {
            path,
            nick,
            properties: None,
            membrane_proof: None,
        })
    }
}

/// App-specific payload for proving membership in the membrane of the app
pub type MembraneProof = SerializedBytes;

/// Data about an installed Cell
#[derive(Clone, Debug, Into, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstalledCell(CellId, CellNick);

impl InstalledCell {
    /// Constructor
    pub fn new(cell_id: CellId, cell_handle: CellNick) -> Self {
        Self(cell_id, cell_handle)
    }

    /// Get the CellId
    pub fn into_id(self) -> CellId {
        self.0
    }

    /// Get the CellNick
    pub fn into_nick(self) -> CellNick {
        self.1
    }

    /// Get the inner data as a tuple
    pub fn into_inner(self) -> (CellId, CellNick) {
        (self.0, self.1)
    }

    /// Get the CellId
    pub fn as_id(&self) -> &CellId {
        &self.0
    }

    /// Get the CellNick
    pub fn as_nick(&self) -> &CellNick {
        &self.1
    }
}

/// A collection of [InstalledCell]s paired with an app id
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstalledApp {
    /// Placeholder to find the app
    pub installed_app_id: InstalledAppId,
    /// Cell data for this app
    pub cell_data: Vec<InstalledCell>,
}
