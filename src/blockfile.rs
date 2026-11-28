// SPDX-License-Identifier: MIT

//! Independent append-only proof and compact undo-leaf storage.

use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;

use crate::block_index::FileIndex;
use crate::udata::decode_leaf_data;
use crate::udata::encode_leaf_data;
use crate::udata::BatchProof;
use crate::udata::CompactLeafData;
use crate::udata::MAX_COMPACT_PROOF_BYTES;

struct RecordFile {
    file: File,
    writer_pos: AtomicU64,
}

impl RecordFile {
    fn new(path: PathBuf) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let writer_pos = file.metadata()?.len();
        usize::try_from(writer_pos)
            .map_err(|_| std::io::Error::other("record file exceeds usize"))?;
        Ok(Self {
            file,
            writer_pos: AtomicU64::new(writer_pos),
        })
    }

    /// Reserve only after serialization, and publish an index only after the full write.
    /// A failed write may leave an unreferenced hole; later reservations never reuse it.
    fn append(&self, buffer: &[u8]) -> std::io::Result<FileIndex> {
        if buffer.len() > MAX_COMPACT_PROOF_BYTES {
            return Err(std::io::Error::other("record exceeds storage limit"));
        }
        let length = u64::try_from(buffer.len())
            .map_err(|_| std::io::Error::other("record length exceeds u64"))?;
        let mut offset = self.writer_pos.load(Ordering::Acquire);
        loop {
            let end = offset
                .checked_add(length)
                .filter(|end| usize::try_from(*end).is_ok())
                .ok_or_else(|| std::io::Error::other("record file offset overflow"))?;
            match self.writer_pos.compare_exchange_weak(
                offset,
                end,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => offset = actual,
            }
        }
        self.file.write_all_at(buffer, offset)?;
        Ok(FileIndex {
            offset: offset as usize,
            size: buffer.len(),
        })
    }

    fn contains(&self, index: &FileIndex) -> bool {
        // File bounds alone cannot authorize allocation from a corrupt sparse-file index.
        index.size <= MAX_COMPACT_PROOF_BYTES
            && index
                .offset
                .checked_add(index.size)
                .and_then(|end| u64::try_from(end).ok())
                .zip(self.file.metadata().ok().map(|metadata| metadata.len()))
                .is_some_and(|(end, file_len)| end <= file_len)
    }

    fn get(&self, index: &FileIndex) -> Option<Vec<u8>> {
        if !self.contains(index) {
            return None;
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(index.size).ok()?;
        bytes.resize(index.size, 0);
        self.file
            .read_exact_at(&mut bytes, index.offset as u64)
            .ok()?;
        Some(bytes)
    }

    fn sync(&self) -> std::io::Result<()> {
        self.file.sync_data()
    }
}

/// Proof targets and hashes only; compact leaves live independently in `LeafFile`.
pub struct ProofFile(RecordFile);

impl ProofFile {
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        Ok(Self(RecordFile::new(path)?))
    }

    pub fn append(&self, proof: &BatchProof) -> std::io::Result<FileIndex> {
        self.0.append(&serialize(proof))
    }

    pub fn contains(&self, index: &FileIndex) -> bool {
        self.0.contains(index)
    }

    pub fn get(&self, index: &FileIndex) -> Option<BatchProof> {
        deserialize(&self.0.get(index)?).ok()
    }

    /// Recovery-only operation: callers must quiesce proof writers before truncation.
    pub fn truncate_after(&self, index: Option<&FileIndex>) -> std::io::Result<()> {
        let end = match index {
            Some(index) => index
                .offset
                .checked_add(index.size)
                .ok_or_else(|| std::io::Error::other("proof index end overflow"))?,
            None => 0,
        };
        let end =
            u64::try_from(end).map_err(|_| std::io::Error::other("proof index exceeds u64"))?;
        if self.0.file.metadata()?.len() < end {
            return Err(std::io::Error::other(format!(
                "proof file ends before published proof offset {end}"
            )));
        }
        self.0.file.set_len(end)?;
        self.0.writer_pos.store(end, Ordering::Release);
        self.sync()
    }

    pub fn sync(&self) -> std::io::Result<()> {
        self.0.sync()
    }
}

/// Permanent compact undo leaves. This file deliberately exposes no truncation operation.
pub struct LeafFile(RecordFile);

impl LeafFile {
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        Ok(Self(RecordFile::new(path)?))
    }

    pub fn append(&self, leaves: &[CompactLeafData]) -> std::io::Result<FileIndex> {
        let mut buffer = Vec::new();
        encode_leaf_data(leaves, &mut buffer)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        self.0.append(&buffer)
    }

    pub fn contains(&self, index: &FileIndex) -> bool {
        self.0.contains(index)
    }

    pub fn get(&self, index: &FileIndex) -> Option<Vec<CompactLeafData>> {
        let bytes = self.0.get(index)?;
        let mut reader = bytes.as_slice();
        let leaves = decode_leaf_data(&mut reader).ok()?;
        reader.is_empty().then_some(leaves)
    }

    pub fn sync(&self) -> std::io::Result<()> {
        self.0.sync()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Barrier;

    use bitcoin::hashes::Hash;
    use bitcoin::BlockHash;
    use bitcoin::VarInt;

    use super::*;
    use crate::udata::CompactBlockProof;
    use crate::udata::ScriptPubkeyType;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "bridge-split-file-{}-{name}.dat",
            std::process::id()
        ))
    }

    fn leaf(amount: u64) -> CompactLeafData {
        CompactLeafData {
            header_code: 42,
            amount,
            spk_ty: ScriptPubkeyType::Other(vec![0x51; amount as usize + 1].into_boxed_slice()),
        }
    }

    #[test]
    fn sparse_file_does_not_authorize_oversized_record_allocation() {
        let path = path("oversized");
        let _ = std::fs::remove_file(&path);
        let file = ProofFile::new(path.clone()).unwrap();
        let index = FileIndex {
            offset: 0,
            size: MAX_COMPACT_PROOF_BYTES + 1,
        };
        file.0.file.set_len(index.size as u64).unwrap();
        assert!(!file.contains(&index));
        assert!(file.get(&index).is_none());
        drop(file);
        let leaves = LeafFile::new(path.clone()).unwrap();
        assert!(!leaves.contains(&index));
        assert!(leaves.get(&index).is_none());
        drop(leaves);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn proof_records_exclude_leaves_and_truncation_preserves_them() {
        let proof_path = path("split-proof");
        let leaf_path = path("split-leaves");
        let _ = std::fs::remove_file(&proof_path);
        let _ = std::fs::remove_file(&leaf_path);
        let proofs = ProofFile::new(proof_path.clone()).unwrap();
        let leaves = LeafFile::new(leaf_path.clone()).unwrap();
        let combined = CompactBlockProof {
            proof: BatchProof {
                targets: vec![VarInt(300)],
                hashes: vec![BlockHash::all_zeros()],
            },
            leaves: vec![leaf(7)],
        };
        let proof_index = proofs.append(&combined.proof).unwrap();
        let leaf_index = leaves.append(&combined.leaves).unwrap();
        proofs.sync().unwrap();
        leaves.sync().unwrap();
        assert_eq!(
            std::fs::read(&proof_path).unwrap(),
            serialize(&combined.proof)
        );
        let mut journal_bytes = std::fs::read(&proof_path).unwrap();
        journal_bytes.extend_from_slice(&std::fs::read(&leaf_path).unwrap());
        assert_eq!(journal_bytes, serialize(&combined));
        assert_eq!(proofs.get(&proof_index), Some(combined.proof));
        proofs.truncate_after(None).unwrap();
        assert!(!proofs.contains(&proof_index));
        assert_eq!(leaves.get(&leaf_index), Some(combined.leaves));
        drop(proofs);
        drop(leaves);
        std::fs::remove_file(proof_path).unwrap();
        std::fs::remove_file(leaf_path).unwrap();
    }

    #[test]
    fn concurrent_leaf_writes_are_disjoint_and_survive_reopen() {
        let path = path("concurrent-leaves");
        let _ = std::fs::remove_file(&path);
        let file = Arc::new(LeafFile::new(path.clone()).unwrap());
        let barrier = Arc::new(Barrier::new(8));
        let handles = (0..8)
            .map(|amount| {
                let file = Arc::clone(&file);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let leaves = vec![leaf(amount)];
                    barrier.wait();
                    (file.append(&leaves).unwrap(), leaves)
                })
            })
            .collect::<Vec<_>>();
        let mut records = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        records.sort_unstable_by_key(|(index, _)| index.offset);
        assert!(records
            .windows(2)
            .all(|pair| { pair[0].0.offset + pair[0].0.size <= pair[1].0.offset }));
        file.sync().unwrap();
        drop(file);
        let file = LeafFile::new(path.clone()).unwrap();
        for (index, leaves) in &records {
            assert_eq!(file.get(index).as_ref(), Some(leaves));
        }
        let next = file.append(&[]).unwrap();
        let last = records.last().unwrap().0;
        assert!(next.offset >= last.offset + last.size);
        assert_eq!(file.get(&next), Some(Vec::new()));
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn concurrent_proof_appends_reserve_disjoint_ranges() {
        let path = path("concurrent-proofs");
        let _ = std::fs::remove_file(&path);
        let file = Arc::new(ProofFile::new(path.clone()).unwrap());
        let barrier = Arc::new(Barrier::new(8));
        let proof = BatchProof::default();
        let handles = (0..8)
            .map(|_| {
                let file = Arc::clone(&file);
                let barrier = Arc::clone(&barrier);
                let proof = proof.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    file.append(&proof).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let mut indexes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        indexes.sort_unstable_by_key(|index| index.offset);
        assert!(indexes
            .windows(2)
            .all(|pair| { pair[0].offset + pair[0].size <= pair[1].offset }));
        file.sync().unwrap();
        drop(file);
        let file = ProofFile::new(path.clone()).unwrap();
        assert!(indexes
            .iter()
            .all(|index| file.get(index).as_ref() == Some(&proof)));
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
}
