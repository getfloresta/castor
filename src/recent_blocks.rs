// SPDX-License-Identifier: MIT

//! Fixed-size block slots, reserved on the first write rather than during IBD.
//!
//! Checksummed metadata commits each payload; an interrupted overwrite is either
//! the old complete block, the new complete block, or an invalid slot. Reopening
//! reads only metadata and leaves serving suspended. Payloads are checked lazily
//! before they can satisfy backfill or publication. A single lock also protects
//! the reusable serialization buffer and prevents reads racing slot overwrites.

use std::fs::File;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::Block;
use bitcoin::BlockHash;
use parking_lot::Mutex;
use sha2::Digest;
use sha2::Sha256;

/// The serving window plus 144 blocks of reorganization headroom.
pub const RETAINED_BLOCKS: u32 = 433;
const SERVING_DEPTH: u32 = 288;
const MAX_BLOCK_BYTES: usize = 4_000_000;
const SLOT_COUNT: usize = RETAINED_BLOCKS as usize;
const METADATA_BYTES: usize = 144;
const MAGIC: &[u8; 8] = b"RCBLK001";

#[derive(Clone, Copy)]
struct Slot {
    height: u32,
    len: usize,
    hash: BlockHash,
    previous: BlockHash,
    checksum: [u8; 32],
    checked: bool,
}

struct State {
    file: File,
    reserved: bool,
    payload_capacity: usize,
    slots: [Option<Slot>; SLOT_COUNT],
    published: [bool; SLOT_COUNT],
    ready: bool,
    buffer: Vec<u8>,
}

pub struct RecentBlocks {
    state: Mutex<State>,
}

impl RecentBlocks {
    /// Opening an empty store neither reserves disk space nor allocates a block buffer.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_capacity(path, MAX_BLOCK_BYTES)
    }

    #[cfg(test)]
    pub(crate) fn open_test(path: &Path) -> Result<Self> {
        Self::open_with_capacity(path, 4096)
    }

    fn open_with_capacity(path: &Path, payload_capacity: usize) -> Result<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("opening recent blocks {}", path.display()))?;
        let file_len = file.metadata()?.len();
        let stride = (METADATA_BYTES + payload_capacity) as u64;
        if file_len > stride * u64::from(RETAINED_BLOCKS) {
            bail!("recent block file exceeds its fixed capacity");
        }
        let mut slots = [None; SLOT_COUNT];
        for (index, slot) in slots.iter_mut().enumerate() {
            let offset = index as u64 * stride;
            if offset + METADATA_BYTES as u64 > file_len {
                break;
            }
            let mut metadata = [0; METADATA_BYTES];
            file.read_exact_at(&mut metadata, offset)?;
            *slot = decode_metadata(&metadata, index, payload_capacity)
                .filter(|entry| offset + METADATA_BYTES as u64 + entry.len as u64 <= file_len);
        }
        Ok(Self {
            state: Mutex::new(State {
                file,
                reserved: false,
                payload_capacity,
                slots,
                published: [false; SLOT_COUNT],
                ready: false,
                buffer: Vec::new(),
            }),
        })
    }

    pub fn put(&self, height: u32, block: &Block) -> Result<()> {
        let mut state = self.state.lock();
        let capacity = state.payload_capacity;
        let len = encode_block(&mut state.buffer, capacity, block)?;
        // Reserve all slots, including metadata, before changing any existing entry.
        // Repeating this once after reopening also repairs an interrupted reservation.
        state.reserve()?;
        let index = (height % RETAINED_BLOCKS) as usize;
        let slot = Slot {
            height,
            len,
            hash: block.block_hash(),
            previous: block.header.prev_blockhash,
            checksum: Sha256::digest(&state.buffer[..len]).into(),
            checked: true,
        };
        state.forget(index);
        let offset = state.offset(index);
        state.file.write_all_at(&[0; METADATA_BYTES], offset)?;
        state
            .file
            .write_all_at(&state.buffer[..len], offset + METADATA_BYTES as u64)?;
        state.file.write_all_at(&encode_metadata(slot), offset)?;
        state.slots[index] = Some(slot);
        Ok(())
    }

    /// This is a backfill cache lookup, not permission to serve the block.
    pub fn contains(&self, height: u32, hash: BlockHash) -> bool {
        let mut state = self.state.lock();
        let index = (height % RETAINED_BLOCKS) as usize;
        let Some(slot) = state.slots[index] else {
            return false;
        };
        if slot.height != height || slot.hash != hash {
            return false;
        }
        if slot.checked {
            return true;
        }
        match state.read_payload(index, slot) {
            Ok(true) => true,
            Ok(false) | Err(_) => {
                state.forget(index);
                false
            }
        }
    }

    pub fn sync(&self) -> Result<()> {
        self.state
            .lock()
            .file
            .sync_data()
            .context("syncing recent blocks")
    }

    /// Publish only a complete, hash-linked window ending at the caller's canonical tip.
    /// Missing blocks are normal during startup/deep rollback and leave serving disabled.
    pub fn set_tip(&self, height: u32, hash: BlockHash) -> Result<()> {
        let mut state = self.state.lock();
        state.suspend();
        let mut removed = false;
        for index in 0..SLOT_COUNT {
            if state.slots[index].is_some_and(|slot| slot.height > height) {
                state.forget(index);
                state
                    .file
                    .write_all_at(&[0; METADATA_BYTES], state.offset(index))?;
                removed = true;
            }
        }
        if removed {
            // A successful rollback must not resurrect orphan entries on reopen.
            state
                .file
                .sync_data()
                .context("syncing recent block rollback")?;
        }
        let first = height.saturating_sub(SERVING_DEPTH);
        let mut expected = hash;
        let mut published = [false; SLOT_COUNT];
        for current in (first..=height).rev() {
            let index = (current % RETAINED_BLOCKS) as usize;
            let Some(slot) = state.slots[index] else {
                return Ok(());
            };
            if slot.height != current || slot.hash != expected {
                return Ok(());
            }
            if !slot.checked {
                match state.read_payload(index, slot) {
                    Ok(true) => {}
                    Ok(false) => {
                        state.forget(index);
                        return Ok(());
                    }
                    Err(error) => {
                        state.forget(index);
                        return Err(error);
                    }
                }
            }
            published[index] = true;
            expected = slot.previous;
        }
        state.published = published;
        state.ready = true;
        Ok(())
    }

    pub fn suspend(&self) {
        self.state.lock().suspend();
    }

    pub fn is_ready(&self) -> bool {
        self.state.lock().ready
    }

    /// The lock spans disk read, checksum verification, and decoding: a concurrent
    /// overwrite can never mix one slot's metadata with another block's payload.
    pub fn get(&self, hash: BlockHash) -> Result<Option<Block>> {
        let mut state = self.state.lock();
        if !state.ready {
            return Ok(None);
        }
        let Some(index) = state.slots.iter().enumerate().position(|(index, slot)| {
            state.published[index] && slot.is_some_and(|slot| slot.hash == hash)
        }) else {
            return Ok(None);
        };
        let slot = state.slots[index].expect("published slots are populated");
        match state.read_payload(index, slot) {
            Ok(true) => {}
            Ok(false) => {
                state.forget(index);
                return Ok(None);
            }
            Err(error) => {
                state.forget(index);
                return Err(error);
            }
        }
        match deserialize(&state.buffer[..slot.len]) {
            Ok(block) => Ok(Some(block)),
            Err(_) => {
                state.forget(index);
                Ok(None)
            }
        }
    }
}

impl State {
    fn offset(&self, index: usize) -> u64 {
        index as u64 * (METADATA_BYTES + self.payload_capacity) as u64
    }

    fn reserve(&mut self) -> Result<()> {
        if self.reserved {
            return Ok(());
        }
        let bytes = (METADATA_BYTES + self.payload_capacity) as u64 * u64::from(RETAINED_BLOCKS);
        let allocation = unsafe {
            libc::posix_fallocate(
                self.file.as_raw_fd(),
                0,
                libc::off_t::try_from(bytes).context("recent block file exceeds off_t")?,
            )
        };
        if allocation != 0 {
            return Err(std::io::Error::from_raw_os_error(allocation))
                .context("reserving fixed recent block slots");
        }
        self.reserved = true;
        Ok(())
    }

    fn suspend(&mut self) {
        self.ready = false;
        self.published.fill(false);
    }

    fn forget(&mut self, index: usize) {
        if self.published[index] {
            self.ready = false;
            self.published[index] = false;
        }
        self.slots[index] = None;
    }

    fn read_payload(&mut self, index: usize, slot: Slot) -> Result<bool> {
        self.buffer.resize(self.payload_capacity, 0);
        self.file.read_exact_at(
            &mut self.buffer[..slot.len],
            index as u64 * (METADATA_BYTES + self.payload_capacity) as u64 + METADATA_BYTES as u64,
        )?;
        let payload = &self.buffer[..slot.len];
        let checksum: [u8; 32] = Sha256::digest(payload).into();
        if checksum != slot.checksum {
            return Ok(false);
        }
        let header: bitcoin::block::Header = match deserialize(&payload[..80]) {
            Ok(header) => header,
            Err(_) => return Ok(false),
        };
        if header.block_hash() != slot.hash || header.prev_blockhash != slot.previous {
            return Ok(false);
        }
        self.slots[index] = Some(Slot {
            checked: true,
            ..slot
        });
        Ok(true)
    }
}

fn encode_block(buffer: &mut Vec<u8>, capacity: usize, block: &Block) -> Result<usize> {
    buffer.resize(capacity, 0);
    // Slice writers stop at the bound instead of allocating a second serialization.
    let mut output = &mut buffer[..];
    block
        .consensus_encode(&mut output)
        .context("block exceeds recent block slot capacity")
}

fn encode_metadata(slot: Slot) -> [u8; METADATA_BYTES] {
    let mut metadata = [0; METADATA_BYTES];
    metadata[..8].copy_from_slice(MAGIC);
    metadata[8..12].copy_from_slice(&slot.height.to_le_bytes());
    metadata[12..16].copy_from_slice(&(slot.len as u32).to_le_bytes());
    metadata[16..48].copy_from_slice(slot.hash.as_byte_array());
    metadata[48..80].copy_from_slice(slot.previous.as_byte_array());
    metadata[80..112].copy_from_slice(&slot.checksum);
    let checksum: [u8; 32] = Sha256::digest(&metadata[..112]).into();
    metadata[112..].copy_from_slice(&checksum);
    metadata
}

fn decode_metadata(bytes: &[u8; METADATA_BYTES], index: usize, capacity: usize) -> Option<Slot> {
    if &bytes[..8] != MAGIC {
        return None;
    }
    let checksum: [u8; 32] = Sha256::digest(&bytes[..112]).into();
    if bytes[112..] != checksum {
        return None;
    }
    let height = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    let len = u32::from_le_bytes(bytes[12..16].try_into().ok()?) as usize;
    if (height % RETAINED_BLOCKS) as usize != index || !(81..=capacity).contains(&len) {
        return None;
    }
    Some(Slot {
        height,
        len,
        hash: BlockHash::from_byte_array(bytes[16..48].try_into().ok()?),
        previous: BlockHash::from_byte_array(bytes[48..80].try_into().ok()?),
        checksum: bytes[80..112].try_into().ok()?,
        checked: false,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use bitcoin::consensus::serialize;
    use bitcoin::constants::genesis_block;
    use bitcoin::Network;
    use bitcoin::ScriptBuf;

    use super::*;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            Self(std::env::temp_dir().join(format!(
                "bridge-recent-blocks-{}-{}.dat",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            )))
        }

        fn open(&self) -> RecentBlocks {
            RecentBlocks::open_test(&self.0).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn chain(last: u32) -> Vec<Block> {
        let mut blocks = vec![genesis_block(Network::Bitcoin)];
        for height in 1..=last {
            let mut block = blocks[0].clone();
            block.header.prev_blockhash = blocks.last().unwrap().block_hash();
            block.header.nonce = height;
            blocks.push(block);
        }
        blocks
    }

    fn fill(ring: &RecentBlocks, blocks: &[Block]) {
        for (height, block) in blocks.iter().enumerate() {
            ring.put(height as u32, block).unwrap();
        }
    }

    fn sized_block(size: usize) -> Block {
        let mut block = genesis_block(Network::Bitcoin);
        // Stay in the same CompactSize width when adjusting to the requested size.
        block.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(vec![0; size - 512]);
        let actual = serialize(&block).len();
        let script_len = block.txdata[0].output[0].script_pubkey.len() + size - actual;
        block.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(vec![0; script_len]);
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        assert_eq!(serialize(&block).len(), size);
        block
    }

    #[test]
    fn lazy_reservation_and_genesis_are_distinct_from_empty() {
        let fixture = Fixture::new();
        let ring = fixture.open();
        assert_eq!(std::fs::metadata(&fixture.0).unwrap().len(), 0);
        let genesis = genesis_block(Network::Bitcoin);
        ring.set_tip(0, genesis.block_hash()).unwrap();
        assert!(!ring.is_ready());
        assert!(!ring.contains(0, genesis.block_hash()));
        ring.put(0, &genesis).unwrap();
        assert_eq!(
            std::fs::metadata(&fixture.0).unwrap().len(),
            (4096 + METADATA_BYTES) as u64 * 433
        );
        let metadata = std::fs::metadata(&fixture.0).unwrap();
        assert!(
            std::os::unix::fs::MetadataExt::blocks(&metadata) * 512 >= metadata.len(),
            "reservation must allocate physical disk blocks, not merely extend the file"
        );
        assert!(ring.get(genesis.block_hash()).unwrap().is_none());
        ring.set_tip(0, genesis.block_hash()).unwrap();
        assert!(ring.is_ready());
        assert_eq!(ring.get(genesis.block_hash()).unwrap(), Some(genesis));
    }

    #[test]
    fn rollover_retains_fixed_slots_but_serves_only_289_blocks() {
        let fixture = Fixture::new();
        let ring = fixture.open();
        let blocks = chain(600);
        fill(&ring, &blocks);
        ring.set_tip(600, blocks[600].block_hash()).unwrap();
        assert!(ring.is_ready());
        assert!(!ring.contains(167, blocks[167].block_hash()));
        assert!(ring.contains(168, blocks[168].block_hash()));
        assert!(ring.get(blocks[168].block_hash()).unwrap().is_none());
        assert!(ring.get(blocks[311].block_hash()).unwrap().is_none());
        assert_eq!(
            ring.get(blocks[312].block_hash()).unwrap(),
            Some(blocks[312].clone())
        );
        assert_eq!(
            ring.get(blocks[600].block_hash()).unwrap(),
            Some(blocks[600].clone())
        );
        assert_eq!(
            std::fs::metadata(&fixture.0).unwrap().len(),
            (4096 + METADATA_BYTES) as u64 * 433
        );
    }

    #[test]
    fn same_height_replacement_invalidates_old_hash_until_publication() {
        let fixture = Fixture::new();
        let ring = fixture.open();
        let blocks = chain(2);
        fill(&ring, &blocks);
        ring.set_tip(2, blocks[2].block_hash()).unwrap();
        let mut replacement = blocks[2].clone();
        replacement.header.nonce += 1;
        ring.put(2, &replacement).unwrap();
        assert!(!ring.is_ready());
        assert!(!ring.contains(2, blocks[2].block_hash()));
        assert!(ring.get(blocks[2].block_hash()).unwrap().is_none());
        assert!(ring.get(replacement.block_hash()).unwrap().is_none());
        ring.set_tip(2, replacement.block_hash()).unwrap();
        assert!(ring.is_ready());
        assert_eq!(
            ring.get(replacement.block_hash()).unwrap(),
            Some(replacement)
        );
        assert!(ring.get(blocks[2].block_hash()).unwrap().is_none());
    }

    #[test]
    fn speculative_writes_preserve_published_tip_until_they_overwrite_it() {
        let fixture = Fixture::new();
        let ring = fixture.open();
        let blocks = chain(433);
        fill(&ring, &blocks[..301]);
        ring.set_tip(300, blocks[300].block_hash()).unwrap();
        for height in 301..433 {
            ring.put(height, &blocks[height as usize]).unwrap();
        }
        assert!(ring.is_ready());
        assert!(ring.get(blocks[432].block_hash()).unwrap().is_none());
        ring.put(433, &blocks[433]).unwrap();
        assert!(ring.is_ready()); // Height zero is outside the published window.
        ring.put(445, &blocks[433]).unwrap(); // Slot 12 is the published lower boundary.
        assert!(!ring.is_ready());
        assert!(ring.get(blocks[300].block_hash()).unwrap().is_none());
    }

    #[test]
    fn rollback_removes_higher_orphans_and_reopen_starts_suspended() {
        let fixture = Fixture::new();
        let blocks = chain(5);
        {
            let ring = fixture.open();
            fill(&ring, &blocks);
            ring.set_tip(5, blocks[5].block_hash()).unwrap();
            ring.suspend();
            assert!(!ring.is_ready());
            assert!(ring.get(blocks[5].block_hash()).unwrap().is_none());
            ring.set_tip(2, blocks[2].block_hash()).unwrap();
            assert!(ring.is_ready());
            assert!(!ring.contains(3, blocks[3].block_hash()));
            assert!(ring.get(blocks[5].block_hash()).unwrap().is_none());
            ring.sync().unwrap();
        }
        let ring = fixture.open();
        assert!(!ring.is_ready());
        assert!(ring.contains(0, blocks[0].block_hash()));
        assert!(ring.get(blocks[2].block_hash()).unwrap().is_none());
        assert!(!ring.contains(3, blocks[3].block_hash()));
        assert!(!ring.contains(5, blocks[5].block_hash()));
        ring.set_tip(2, blocks[2].block_hash()).unwrap();
        assert!(ring.is_ready());
        assert_eq!(
            ring.get(blocks[2].block_hash()).unwrap(),
            Some(blocks[2].clone())
        );
    }

    #[test]
    fn deep_rollback_removes_orphans_even_without_retained_tip() {
        let fixture = Fixture::new();
        let blocks = chain(500);
        {
            let ring = fixture.open();
            fill(&ring, &blocks);
            ring.set_tip(500, blocks[500].block_hash()).unwrap();
            ring.set_tip(1, blocks[1].block_hash()).unwrap();
            assert!(!ring.is_ready());
            assert!(!ring.contains(500, blocks[500].block_hash()));
        }
        let ring = fixture.open();
        assert!(!ring.contains(500, blocks[500].block_hash()));
        assert!(!ring.contains(68, blocks[68].block_hash()));
    }

    #[test]
    fn exact_slot_limit_succeeds_and_oversize_preserves_published_block() {
        let fixture = Fixture::new();
        let ring = fixture.open();
        let exact = sized_block(4096);
        ring.put(0, &exact).unwrap();
        ring.set_tip(0, exact.block_hash()).unwrap();
        assert!(ring.is_ready());
        assert!(ring.put(0, &sized_block(4097)).is_err());
        assert!(ring.is_ready());
        assert_eq!(ring.get(exact.block_hash()).unwrap(), Some(exact));
    }

    #[test]
    fn production_payload_limit_is_exactly_four_million_bytes() {
        let mut buffer = Vec::new();
        assert_eq!(
            encode_block(&mut buffer, MAX_BLOCK_BYTES, &sized_block(4_000_000)).unwrap(),
            4_000_000
        );
        assert!(encode_block(&mut buffer, MAX_BLOCK_BYTES, &sized_block(4_000_001)).is_err());
        assert_eq!(buffer.len(), MAX_BLOCK_BYTES);
    }

    #[test]
    fn torn_payload_on_reopen_cannot_satisfy_backfill_or_readiness() {
        let fixture = Fixture::new();
        let blocks = chain(3);
        {
            let ring = fixture.open();
            fill(&ring, &blocks);
            ring.sync().unwrap();
        }
        let file = OpenOptions::new().write(true).open(&fixture.0).unwrap();
        // Leave valid metadata but corrupt transaction bytes, not just the header.
        file.write_all_at(
            &[0xff],
            (4096 + METADATA_BYTES) as u64 + METADATA_BYTES as u64 + 100,
        )
        .unwrap();
        let ring = fixture.open();
        ring.set_tip(3, blocks[3].block_hash()).unwrap();
        assert!(!ring.is_ready());
        assert!(!ring.contains(1, blocks[1].block_hash()));
        assert!(ring.get(blocks[3].block_hash()).unwrap().is_none());
        ring.put(1, &blocks[1]).unwrap();
        ring.set_tip(3, blocks[3].block_hash()).unwrap();
        assert!(ring.is_ready());
    }

    #[test]
    fn torn_metadata_on_reopen_cannot_advertise_or_serve() {
        let fixture = Fixture::new();
        let blocks = chain(2);
        {
            let ring = fixture.open();
            fill(&ring, &blocks);
            ring.sync().unwrap();
        }
        let file = OpenOptions::new().write(true).open(&fixture.0).unwrap();
        file.write_all_at(&[0xff], (4096 + METADATA_BYTES) as u64 + 12)
            .unwrap();
        let ring = fixture.open();
        assert!(!ring.contains(1, blocks[1].block_hash()));
        ring.set_tip(2, blocks[2].block_hash()).unwrap();
        assert!(!ring.is_ready());
        assert!(ring.get(blocks[2].block_hash()).unwrap().is_none());
    }

    #[test]
    fn corrupted_served_payload_disables_readiness() {
        let fixture = Fixture::new();
        let ring = fixture.open();
        let blocks = chain(1);
        fill(&ring, &blocks);
        ring.set_tip(1, blocks[1].block_hash()).unwrap();
        let file = OpenOptions::new().write(true).open(&fixture.0).unwrap();
        file.write_all_at(&[0xff], METADATA_BYTES as u64 + 100)
            .unwrap();
        assert!(ring.get(blocks[0].block_hash()).unwrap().is_none());
        assert!(!ring.is_ready());
        assert!(ring.get(blocks[1].block_hash()).unwrap().is_none());
    }

    #[test]
    fn concurrent_reads_never_decode_overwritten_slot_bytes() {
        let fixture = Fixture::new();
        let ring = std::sync::Arc::new(fixture.open());
        let first = genesis_block(Network::Bitcoin);
        let mut second = first.clone();
        second.header.nonce += 1;
        ring.put(0, &first).unwrap();
        ring.set_tip(0, first.block_hash()).unwrap();
        let reader_ring = ring.clone();
        let reader_block = first.clone();
        let reader = std::thread::spawn(move || {
            for _ in 0..200 {
                if let Some(block) = reader_ring.get(reader_block.block_hash()).unwrap() {
                    assert_eq!(block, reader_block);
                }
            }
        });
        for _ in 0..100 {
            ring.put(0, &second).unwrap();
            ring.set_tip(0, second.block_hash()).unwrap();
            ring.put(0, &first).unwrap();
            ring.set_tip(0, first.block_hash()).unwrap();
        }
        reader.join().unwrap();
    }

    #[test]
    fn disconnected_chain_cannot_be_published() {
        let fixture = Fixture::new();
        let ring = fixture.open();
        let blocks = chain(2);
        fill(&ring, &blocks);
        let mut disconnected = blocks[1].clone();
        disconnected.header.nonce += 100;
        ring.put(1, &disconnected).unwrap();
        ring.set_tip(2, blocks[2].block_hash()).unwrap();
        assert!(!ring.is_ready());
        assert!(ring.get(blocks[2].block_hash()).unwrap().is_none());
    }
}
