//SPDX-License-Identifier: MIT

//! Rebuildable header cache. Appends never unlink records while peers read them.
//! Clean shutdown checkpoints the cache; after a crash, missing entries are fetched
//! again from the canonical header index or Bitcoin Core.

use std::path::Path;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::hashes::HashEngine;
use bitcoin::BlockHash;
use floresta_db::Config;
use floresta_db::Database;
use floresta_db::Mode;

pub struct ChainView {
    storage: Database,
}

impl ChainView {
    pub fn open(path: &Path) -> Result<Self> {
        let storage = if path.exists() {
            if !path.join("heads").is_file() {
                bail!(
                    "legacy chain-view database at {}; rebuild bridge storage",
                    path.display()
                );
            }
            Database::open(path).context("failed to recover chain-view cache")?
        } else {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent)?;
            }
            let mut config = Config::new(Mode::Map, 1 << 16);
            config.block_size = 1 << 20;
            config.body_capacity = 1 << 30;
            config.blob_capacity = 4 << 30;
            let storage = Database::create(path, config)?;
            storage.checkpoint()?;
            storage
        };
        Ok(Self { storage })
    }

    pub fn get_acc(&self, hash: BlockHash) -> Result<Option<Vec<u8>>> {
        self.get(0, hash.as_byte_array())
    }

    pub fn get_block(&self, hash: BlockHash) -> Result<Option<Vec<u8>>> {
        self.get(1, hash.as_byte_array())
    }

    pub fn get_block_hash(&self, height: u32) -> Result<Option<BlockHash>> {
        self.get(2, &height.to_be_bytes())?
            .map(|hash| BlockHash::from_slice(&hash).context("invalid cached block hash"))
            .transpose()
    }

    pub fn save_header(&self, hash: BlockHash, header: Vec<u8>) -> Result<()> {
        self.append(1, hash.as_byte_array(), &header)
    }

    pub fn save_block_hash(&self, height: u32, hash: BlockHash) -> Result<()> {
        self.append(2, &height.to_be_bytes(), hash.as_byte_array())
    }

    pub fn get_height(&self, hash: BlockHash) -> Result<Option<u32>> {
        self.get(3, hash.as_byte_array())?
            .map(|height| {
                let height = height
                    .as_slice()
                    .try_into()
                    .context("invalid cached height")?;
                Ok(u32::from_be_bytes(height))
            })
            .transpose()
    }

    pub fn save_height(&self, hash: BlockHash, height: u32) -> Result<()> {
        self.append(3, hash.as_byte_array(), &height.to_be_bytes())
    }

    fn key(namespace: u8, identity: &[u8]) -> [u8; 16] {
        let mut engine = sha256::Hash::engine();
        engine.input(&[namespace]);
        engine.input(identity);
        let hash = sha256::Hash::from_engine(engine);
        let mut key = [0; 16];
        key.copy_from_slice(&hash.as_byte_array()[..16]);
        key
    }

    fn get(&self, namespace: u8, identity: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(mut record) = self.storage.get(&Self::key(namespace, identity))? else {
            return Ok(None);
        };
        // The database key is only 128 bits. Never serve another full identity's data.
        if record.first() != Some(&namespace) || record.get(1..1 + identity.len()) != Some(identity)
        {
            bail!("chain-view cache key collision or corrupt record");
        }
        record.drain(..1 + identity.len());
        Ok(Some(record))
    }

    fn append(&self, namespace: u8, identity: &[u8], value: &[u8]) -> Result<()> {
        if self.get(namespace, identity)?.as_deref() == Some(value) {
            return Ok(());
        }
        let key = Self::key(namespace, identity);
        let mut record = Vec::with_capacity(1 + identity.len() + value.len());
        record.push(namespace);
        record.extend_from_slice(identity);
        record.extend_from_slice(value);
        self.storage
            .write_only()?
            .put_batch([(key.as_slice(), record.as_slice())])?;
        Ok(())
    }
}

impl Drop for ChainView {
    fn drop(&mut self) {
        // All Arc<ChainView> readers have left before this quiescent checkpoint.
        if let Err(error) = self.storage.checkpoint() {
            log::warn!("failed to checkpoint rebuildable chain-view cache: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn concurrent_cached_headers_and_reorg_mapping_survive_reopen() {
        let path = std::env::temp_dir().join(format!("bridge-chainview-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let cache = Arc::new(ChainView::open(&path).unwrap());
        std::thread::scope(|scope| {
            for byte in 1..=8u8 {
                let cache = Arc::clone(&cache);
                scope.spawn(move || {
                    let hash = BlockHash::from_byte_array([byte; 32]);
                    cache.save_header(hash, vec![byte; 80]).unwrap();
                    cache.save_height(hash, u32::from(byte)).unwrap();
                    cache.save_block_hash(u32::from(byte), hash).unwrap();
                    assert_eq!(cache.get_block(hash).unwrap(), Some(vec![byte; 80]));
                    assert_eq!(cache.get_height(hash).unwrap(), Some(u32::from(byte)));
                });
            }
        });
        let replacement = BlockHash::from_byte_array([42; 32]);
        cache.save_block_hash(3, replacement).unwrap();
        drop(cache);
        let cache = ChainView::open(&path).unwrap();
        assert_eq!(cache.get_block_hash(3).unwrap(), Some(replacement));
        for byte in 1..=8u8 {
            let hash = BlockHash::from_byte_array([byte; 32]);
            assert_eq!(cache.get_block(hash).unwrap(), Some(vec![byte; 80]));
            assert_eq!(cache.get_height(hash).unwrap(), Some(u32::from(byte)));
            if byte != 3 {
                assert_eq!(cache.get_block_hash(u32::from(byte)).unwrap(), Some(hash));
            }
        }
        drop(cache);
        std::fs::remove_dir_all(path).unwrap();
    }
}
