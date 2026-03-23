//! Persistence for pending offchain spends.
//!
//! Between `submit` and `finalize` of an Arkade offchain transaction, a crash
//! or network error can leave the transaction pending on the server. Without
//! tracking this state, retrying would attempt to submit a *new* transaction
//! with the same inputs — which fails because they're already locked.
//!
//! [`SpendStore`] is the trait that backends implement. A file-based default
//! ([`FileSpendStore`]) is provided.

use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{Context, Result};
use bitcoin::Psbt;
use bitcoin::base64::{Engine, engine::general_purpose::STANDARD};
use bitcoin::hashes::{Hash, sha256};

/// State persisted between submit and finalize.
///
/// Contains everything needed to resume finalization after a crash:
/// the ark txid and the fully-signed checkpoint PSBTs (all party +
/// server signatures already merged).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingSpend {
    /// Application-level identifier (e.g. trade ID).
    pub id: String,
    /// The Arkade transaction ID (hex).
    pub ark_txid: String,
    /// Fully-signed checkpoint PSBTs (base64-encoded), ready for finalize.
    pub signed_checkpoints: Vec<String>,
}

/// Trait for persisting pending spends.
pub trait SpendStore {
    /// Persist a pending spend. Overwrites any existing entry for the same ID.
    fn save(&self, spend: &PendingSpend) -> Result<()>;

    /// Load a pending spend by its application-level ID.
    fn load(&self, id: &str) -> Result<Option<PendingSpend>>;

    /// Remove a pending spend (called after successful finalization).
    fn remove(&self, id: &str) -> Result<()>;
}

/// File-based [`SpendStore`]: one JSON file per pending spend in a directory.
pub struct FileSpendStore {
    dir: PathBuf,
}

impl FileSpendStore {
    /// Create a new file-based store. The directory is created if it doesn't
    /// exist.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating spend store directory: {}", dir.display()))?;
        Ok(Self { dir })
    }

    fn path_for(&self, id: &str) -> PathBuf {
        // Hash the ID to get a fixed-length, collision-free, path-safe filename.
        let hash = sha256::Hash::hash(id.as_bytes());
        let mut hex = String::with_capacity(64);
        for byte in AsRef::<[u8]>::as_ref(&hash) {
            write!(hex, "{byte:02x}").expect("hex write");
        }
        self.dir.join(format!("{hex}.json"))
    }
}

impl SpendStore for FileSpendStore {
    fn save(&self, spend: &PendingSpend) -> Result<()> {
        let path = self.path_for(&spend.id);
        let json = serde_json::to_string_pretty(spend).context("serializing pending spend")?;

        // Write to a temp file and rename for atomicity.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &json).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("renaming {} → {}", tmp.display(), path.display()))?;

        Ok(())
    }

    fn load(&self, id: &str) -> Result<Option<PendingSpend>> {
        let path = self.path_for(id);
        match std::fs::read_to_string(&path) {
            Ok(json) => {
                let spend: PendingSpend = serde_json::from_str(&json)
                    .with_context(|| format!("parsing {}", path.display()))?;
                Ok(Some(spend))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    fn remove(&self, id: &str) -> Result<()> {
        let path = self.path_for(id);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }
}

// --- Helpers for PSBT ↔ base64 conversion ---

/// Encode a PSBT as a base64 string.
pub fn psbt_to_base64(psbt: &Psbt) -> String {
    STANDARD.encode(psbt.serialize())
}

/// Decode a base64 string into a PSBT.
pub fn psbt_from_base64(s: &str) -> Result<Psbt> {
    let bytes = STANDARD.decode(s).context("base64 decode")?;
    Psbt::deserialize(&bytes).context("PSBT deserialize")
}
