// SPDX-License-Identifier: MIT

use std::path::Path;

use anyhow::bail;
use anyhow::ensure;
use anyhow::Context;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use floresta_db::Config;
use floresta_db::Database;
use floresta_db::Mode;

/// A byte range in one flat file. Its owning field identifies the file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIndex {
    pub offset: usize,
    pub size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofIndex {
    pub file: FileIndex,
    /// Logical forest rows at creation; targets already use the 63-row wire layout.
    pub forest_rows: u8,
}

/// Leaf data survives independently of the optional accumulator proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockIndex {
    pub leaf_data: FileIndex,
    pub proof: Option<ProofIndex>,
}

const HEIGHT_KEY: [u8; 16] = *b"serving-height\0\0";
const BLOCK_RECORD: u8 = 1;
const HEIGHT_RECORD: u8 = 2;
const LEAF_ONLY_BYTES: usize = 50;
const WITH_PROOF_BYTES: usize = 67;

/// Append-only logical versions allow concurrent readers without reclamation locks.
///
/// All publication uses `write_only().put_batch()`: replacing `put`, deletion and
/// compaction are forbidden while readers are active. A checkpoint retains the
/// newest version of each key. Reopening always uses that crash-safe checkpoint,
/// never the potentially incomplete mutable runtime files.
pub struct BlocksIndex {
    database: Database,
}

impl BlocksIndex {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let database = if path.join("heads").exists() {
            Database::open(path).context("opening block index checkpoint")?
        } else {
            if path.exists() {
                ensure!(
                    std::fs::read_dir(path)?.next().is_none(),
                    "legacy or unrecognized block index at {}; rebuild the index and split proof/leaf files before opening",
                    path.display()
                );
                // Database::create requires an absent directory, not an empty one.
                std::fs::remove_dir(path)?;
            }
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent)?;
            }
            let mut config = Config::new(Mode::Map, 1 << 18);
            // Sparse virtual limits; backing files grow only as records are appended.
            config.body_capacity = 4 << 30;
            config.blob_capacity = 4 << 30;
            let database = Database::create(path, config)?;
            database
                .checkpoint()
                .context("initializing block index checkpoint")?;
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            std::fs::File::open(parent)?.sync_all()?;
            database
        };
        Ok(Self { database })
    }

    pub fn get_index(&self, block: BlockHash) -> anyhow::Result<Option<BlockIndex>> {
        let key = block_key(&block)?;
        self.database
            .get(key)?
            .map(|bytes| decode_index(&bytes, block))
            .transpose()
    }

    /// Publish a complete record without flushing. Call `sync` after its flat files
    /// have been synced, or use `append_batch` at the canonical publication boundary.
    pub fn append(&self, index: BlockIndex, block: BlockHash) -> anyhow::Result<()> {
        let key = block_key(&block)?;
        // Reject truncated-key collisions rather than silently replacing another hash.
        self.get_index(block)?;
        let bytes = encode_index(index, block)?;
        self.database
            .write_only()?
            .put_batch([(key, bytes.as_slice())])?;
        Ok(())
    }

    /// Publish a batch and make all completed appends recoverable after a crash.
    /// Flat-file durability must precede this call. Durability boundaries must be
    /// serialized by the publisher; ordinary appends and readers may overlap them.
    pub fn append_batch(&self, indexes: &[(BlockIndex, BlockHash)]) -> anyhow::Result<()> {
        for (index, block) in indexes {
            self.append(*index, *block)?;
        }
        self.sync()
    }

    pub fn sync(&self) -> anyhow::Result<()> {
        self.database.checkpoint()?;
        Ok(())
    }

    /// Persist the serving height only after publishing its associated block records.
    pub fn update_height(&self, height: usize) -> anyhow::Result<()> {
        let mut bytes = [0; 9];
        bytes[0] = HEIGHT_RECORD;
        bytes[1..].copy_from_slice(&u64::try_from(height)?.to_be_bytes());
        self.database
            .write_only()?
            .put_batch([(HEIGHT_KEY.as_slice(), bytes.as_slice())])?;
        self.sync()
    }

    pub fn load_height(&self) -> anyhow::Result<usize> {
        let Some(bytes) = self.database.get(&HEIGHT_KEY)? else {
            return Ok(0);
        };
        ensure!(
            bytes.len() == 9 && bytes[0] == HEIGHT_RECORD,
            "invalid serving height record"
        );
        Ok(usize::try_from(u64::from_be_bytes(bytes[1..].try_into()?))?)
    }

    /// Append a leaf-only logical version; never delete the block's undo data.
    pub fn remove_proof(&self, block: BlockHash) -> anyhow::Result<()> {
        if let Some(mut index) = self.get_index(block)? {
            index.proof = None;
            self.append(index, block)?;
            self.sync()?;
        }
        Ok(())
    }
}

fn block_key(block: &BlockHash) -> anyhow::Result<&[u8]> {
    let key = &block.as_byte_array()[..16];
    ensure!(
        key != HEIGHT_KEY,
        "block hash collides with serving height key"
    );
    Ok(key)
}

fn encode_file(index: FileIndex, bytes: &mut Vec<u8>) -> anyhow::Result<()> {
    ensure!(
        index.offset.checked_add(index.size).is_some(),
        "file index end overflow"
    );
    bytes.extend_from_slice(&u64::try_from(index.offset)?.to_be_bytes());
    bytes.extend_from_slice(&u64::try_from(index.size)?.to_be_bytes());
    Ok(())
}

fn encode_index(index: BlockIndex, block: BlockHash) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(if index.proof.is_some() {
        WITH_PROOF_BYTES
    } else {
        LEAF_ONLY_BYTES
    });
    bytes.push(BLOCK_RECORD);
    bytes.extend_from_slice(block.as_byte_array());
    encode_file(index.leaf_data, &mut bytes)?;
    match index.proof {
        None => bytes.push(0),
        Some(proof) => {
            ensure!(proof.forest_rows <= 63, "proof forest rows exceeds 63");
            bytes.push(1);
            encode_file(proof.file, &mut bytes)?;
            bytes.push(proof.forest_rows);
        }
    }
    Ok(bytes)
}

fn decode_file(bytes: &[u8]) -> anyhow::Result<FileIndex> {
    let offset = usize::try_from(u64::from_be_bytes(bytes[..8].try_into()?))?;
    let size = usize::try_from(u64::from_be_bytes(bytes[8..16].try_into()?))?;
    ensure!(
        offset.checked_add(size).is_some(),
        "file index end overflow"
    );
    Ok(FileIndex { offset, size })
}

fn decode_index(bytes: &[u8], block: BlockHash) -> anyhow::Result<BlockIndex> {
    ensure!(
        matches!(bytes.len(), LEAF_ONLY_BYTES | WITH_PROOF_BYTES),
        "invalid block index record length"
    );
    ensure!(bytes[0] == BLOCK_RECORD, "invalid block index record kind");
    ensure!(
        bytes[1..33] == block.as_byte_array()[..],
        "block index full hash mismatch (truncated-key collision or corruption)"
    );
    let leaf_data = decode_file(&bytes[33..49])?;
    let proof = match (bytes[49], bytes.len()) {
        (0, LEAF_ONLY_BYTES) => None,
        (1, WITH_PROOF_BYTES) => {
            ensure!(bytes[66] <= 63, "proof forest rows exceeds 63");
            Some(ProofIndex {
                file: decode_file(&bytes[50..66])?,
                forest_rows: bytes[66],
            })
        }
        _ => bail!("invalid optional proof index encoding"),
    };
    Ok(BlockIndex { leaf_data, proof })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("bridge-block-index-{}-{name}", std::process::id()))
    }

    fn leaf_only() -> BlockIndex {
        BlockIndex {
            leaf_data: FileIndex {
                offset: 42,
                size: 24,
            },
            proof: None,
        }
    }

    #[test]
    fn rejects_malformed_records_and_full_hash_mismatch() {
        let block = BlockHash::all_zeros();
        for length in [0, 16, 49, 51, 66, 68] {
            assert!(decode_index(&vec![0; length], block).is_err());
        }
        let mut index = leaf_only();
        index.proof = Some(ProofIndex {
            file: FileIndex {
                offset: 17,
                size: 32,
            },
            forest_rows: 63,
        });
        let mut bytes = encode_index(index, block).unwrap();
        assert_eq!(decode_index(&bytes, block).unwrap(), index);
        bytes[66] = 64;
        assert!(decode_index(&bytes, block).is_err());
        bytes[66] = 63;
        bytes[32] = 1;
        assert!(decode_index(&bytes, block).is_err());
        index.proof.as_mut().unwrap().forest_rows = 64;
        assert!(encode_index(index, block).is_err());
    }

    #[test]
    fn leaf_only_and_removed_proofs_survive_checkpoint_reopen() {
        let path = path("persistence");
        let _ = std::fs::remove_dir_all(&path);
        let first = BlockHash::from_byte_array([1; 32]);
        let second = BlockHash::from_byte_array([2; 32]);
        let index = leaf_only();
        let mut proved = index;
        proved.proof = Some(ProofIndex {
            file: FileIndex {
                offset: 100,
                size: 99,
            },
            forest_rows: 31,
        });
        let store = BlocksIndex::open(&path).unwrap();
        store
            .append_batch(&[(index, first), (proved, second)])
            .unwrap();
        store.update_height(123).unwrap();
        assert_eq!(store.get_index(second).unwrap(), Some(proved));
        store.remove_proof(second).unwrap();
        assert_eq!(store.get_index(second).unwrap(), Some(index));
        drop(store);
        let store = BlocksIndex::open(&path).unwrap();
        assert_eq!(store.get_index(first).unwrap(), Some(index));
        assert_eq!(store.get_index(second).unwrap(), Some(index));
        assert_eq!(store.load_height().unwrap(), 123);
        // Recovery chooses the checkpoint, not later unsynced runtime publications.
        store.append(proved, second).unwrap();
        drop(store);
        let store = BlocksIndex::open(&path).unwrap();
        assert_eq!(store.get_index(second).unwrap(), Some(index));
        drop(store);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn rejects_legacy_directory_and_truncated_hash_collisions() {
        let path = path("legacy");
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("conf"), b"old store").unwrap();
        assert!(BlocksIndex::open(&path).is_err());
        std::fs::remove_dir_all(&path).unwrap();
        let store = BlocksIndex::open(&path).unwrap();
        let first = BlockHash::all_zeros();
        let mut collision = [0; 32];
        collision[31] = 1;
        let collision = BlockHash::from_byte_array(collision);
        store.append(leaf_only(), first).unwrap();
        assert!(store.get_index(collision).is_err());
        assert!(store.append(leaf_only(), collision).is_err());
        assert_eq!(store.get_index(first).unwrap(), Some(leaf_only()));
        drop(store);
        std::fs::remove_dir_all(path).unwrap();
    }
}
