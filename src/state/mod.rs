use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A node in the Merkle Mountain Range (MMR).
/// This represents the 'mmr_nodes' schema for institutional state attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MmrNode {
    pub hash: [u8; 32],
    pub pos: u64,
    pub height: u32,
}

/// A structured MMR Inclusion Proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmrInclusionProof {
    pub pos: u64,
    pub leaf_hash: String,
    pub proof_path: Vec<String>,
    pub mmr_root: String,
}

/// MMR implementation for cryptographic state attestation.
pub struct MerkleMountainRange {
    pub nodes: Vec<MmrNode>,
}

impl Default for MerkleMountainRange {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleMountainRange {
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Calculate height of a node at position `pos` (1-based).
    pub fn get_height(mut pos: u64) -> u32 {
        if pos == 0 {
            return 0;
        }
        while pos > 0 {
            let mut h = 0;
            while let Some(next_size) = 1u64.checked_shl(h + 1).map(|v| v.saturating_sub(1)) {
                if next_size <= pos {
                    h += 1;
                } else {
                    break;
                }
            }
            let size = (1u64 << h).saturating_sub(1);
            if pos == size {
                return h.saturating_sub(1);
            }
            pos = pos.saturating_sub(size);
        }
        0
    }

    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    pub fn combine_hashes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    pub fn append(&mut self, data: &[u8]) -> u64 {
        let leaf_hash = Self::hash(data);
        let mut pos = self.nodes.len() as u64 + 1;
        let mut height = 0;

        self.nodes.push(MmrNode {
            hash: leaf_hash,
            pos,
            height,
        });

        let leaf_pos = pos;

        while Self::get_height(pos + 1) > height {
            let right_hash = self
                .nodes
                .get(pos as usize - 1)
                .map(|n| n.hash)
                .unwrap_or([0; 32]);
            let left_pos = pos.saturating_sub((1u64 << (height + 1)).saturating_sub(1));
            let left_hash = if left_pos > 0 {
                self.nodes
                    .get(left_pos as usize - 1)
                    .map(|n| n.hash)
                    .unwrap_or([0; 32])
            } else {
                [0; 32]
            };

            let parent_hash = Self::combine_hashes(&left_hash, &right_hash);
            pos += 1;
            height += 1;

            self.nodes.push(MmrNode {
                hash: parent_hash,
                pos,
                height,
            });
        }

        leaf_pos
    }

    pub fn get_peaks(&self) -> Vec<[u8; 32]> {
        let mut peaks = Vec::new();
        let mut cursor = self.nodes.len() as u64;

        while cursor > 0 {
            let height = Self::get_height(cursor);
            if let Some(node) = self.nodes.get(cursor as usize - 1) {
                peaks.push(node.hash);
            }
            let size = (1u64 << (height + 1)).saturating_sub(1);
            if cursor <= size {
                break;
            }
            cursor = cursor.saturating_sub(size);
        }
        peaks.reverse();
        peaks
    }

    pub fn get_root(&self) -> String {
        let peaks = self.get_peaks();
        if peaks.is_empty() {
            return "".to_string();
        }
        let mut root = peaks[0];
        for peak in peaks.iter().skip(1) {
            root = Self::combine_hashes(&root, peak);
        }
        hex::encode(root)
    }

    pub fn generate_proof(&self, pos: u64) -> Result<MmrInclusionProof, String> {
        if pos == 0 || pos > self.nodes.len() as u64 {
            return Err("Position out of range".to_string());
        }

        let mut proof_path = Vec::new();
        let mut current_pos = pos;
        let mut current_height = Self::get_height(current_pos);

        while current_height < Self::get_height(self.nodes.len() as u64)
            || current_pos < self.nodes.len() as u64
        {
            let next_height = Self::get_height(current_pos + 1);
            if next_height > current_height {
                // current_pos is a right sibling
                let size = (1u64 << (current_height + 1)).saturating_sub(1);
                let sibling_pos = current_pos.saturating_sub(size);
                if let Some(node) = sibling_pos
                    .checked_sub(1)
                    .and_then(|idx| self.nodes.get(idx as usize))
                {
                    proof_path.push(hex::encode(node.hash));
                }
                current_pos += 1;
                current_height += 1;
            } else {
                // current_pos might be a left sibling or a peak
                let size = (1u64 << (current_height + 1)).saturating_sub(1);
                let sibling_pos = current_pos + size;
                if sibling_pos <= self.nodes.len() as u64 {
                    if let Some(node) = self.nodes.get(sibling_pos as usize - 1) {
                        proof_path.push(hex::encode(node.hash));
                    }
                    current_pos = sibling_pos + 1;
                    current_height += 1;
                } else {
                    // current_pos is a peak
                    break;
                }
            }
        }

        // Add other peaks to the proof
        let peaks = self.get_peaks();
        let leaf_peak_hash = self
            .nodes
            .get(current_pos as usize - 1)
            .map(|n| n.hash)
            .unwrap_or([0; 32]);
        let mut peak_found = false;
        for peak in peaks {
            if peak_found {
                proof_path.push(hex::encode(peak));
            } else if peak == leaf_peak_hash {
                peak_found = true;
            }
        }

        Ok(MmrInclusionProof {
            pos,
            leaf_hash: hex::encode(
                self.nodes
                    .get(pos as usize - 1)
                    .map(|n| n.hash)
                    .unwrap_or([0; 32]),
            ),
            proof_path,
            mmr_root: self.get_root(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmr_height_calculation() {
        assert_eq!(MerkleMountainRange::get_height(1), 0);
        assert_eq!(MerkleMountainRange::get_height(2), 0);
        assert_eq!(MerkleMountainRange::get_height(3), 1);
        assert_eq!(MerkleMountainRange::get_height(4), 0);
        assert_eq!(MerkleMountainRange::get_height(7), 2);
    }

    #[test]
    fn test_mmr_integrity() {
        let mut mmr = MerkleMountainRange::new();
        mmr.append(b"leaf1");
        mmr.append(b"leaf2");
        mmr.append(b"leaf3");

        assert_eq!(mmr.nodes.len(), 4); // 1, 2 -> 3 (parent), 4 (leaf)
        assert_eq!(mmr.get_peaks().len(), 2); // 3 and 4
    }

    #[test]
    fn test_mmr_proof_generation() {
        let mut mmr = MerkleMountainRange::new();
        let pos1 = mmr.append(b"leaf1");
        let _pos2 = mmr.append(b"leaf2");
        let proof = mmr.generate_proof(pos1).unwrap();
        assert_eq!(proof.pos, pos1);
        assert!(!proof.mmr_root.is_empty());
        assert_eq!(proof.proof_path.len(), 1); // sibling is leaf2
    }
}
