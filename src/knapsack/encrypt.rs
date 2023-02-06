use crate::knapsack::{knapsack_eval, Error, MerkleHellman, MerkleHellmanPublicKey, Result};
use bytes::{BufMut, Bytes, BytesMut};

pub trait Encrypt {
    /// Ability to encrypts the given plaintext fallibly.
    fn encrypt(&self, data: &Bytes) -> Result<Bytes>;
}

impl<const N: usize> Encrypt for MerkleHellman<N> {
    fn encrypt(&self, data: &Bytes) -> Result<Bytes> {
        self.pub_key.encrypt(data)
    }
}

impl<const N: usize> Encrypt for MerkleHellmanPublicKey<N> {
    /// Encrypts a message using the Merkle-Hellman Knapsack Cryptosystem.
    /// Note:
    ///    - The message must not contain any null-byte blocks because those
    ///      are cryptographically insecure as they map the plaintext to itself as a ciphertext.
    fn encrypt(&self, data: &Bytes) -> Result<Bytes> {
        let mut bytes = BytesMut::new();

        if N == 0 {
            return Err(Error::TooShortBlockSize);
        }

        if !matches!(N, 8 | 16 | 32) {
            return Err(Error::InvalidBlockSize);
        }

        let block_size = (N / 8) as u64;

        let exact_chunks = data.chunks_exact(block_size as usize);
        let last_chunk_block_index = exact_chunks.len() as u64;
        let remainder_chunk = exact_chunks.remainder();

        for (idx, block) in exact_chunks.enumerate() {
            let num = match N {
                8 => u8::from_le_bytes([block[0]]) as u64,
                16 => u16::from_le_bytes([block[0], block[1]]) as u64,
                32 => u32::from_le_bytes([block[0], block[1], block[2], block[3]]) as u64,
                _ => unreachable!("N should be 8, 16, or 32."),
            };
            let idx = idx as u64;
            if num == 0 {
                return Err(Error::NullByteBlockFound(
                    block_size * idx,
                    block_size * idx + block_size,
                ));
            }
            let computed_value = knapsack_eval::<u64, N>(num, &self.knapsack.sequence);
            bytes.put_u64(computed_value);
        }

        // We must always pad the last block with 0s on the right.
        // This is because the knapsack algorithm only works on complete blocks of 8/16/32 bits.
        match remainder_chunk.is_empty() {
            true => {
                // Send a whole 0 block of to indicate end of message.
                bytes.put_u64(0);
            }
            false => {
                let mut block = [0u8; N];
                block[..remainder_chunk.len()].copy_from_slice(remainder_chunk);

                let num = match N {
                    8 => u8::from_le_bytes([block[0]]) as u64,
                    16 => u16::from_le_bytes([block[0], block[1]]) as u64,
                    32 => u32::from_le_bytes([block[0], block[1], block[2], block[3]]) as u64,
                    _ => unreachable!("N should be 8, 16, or 32."),
                };

                if num == 0 {
                    return Err(Error::NullByteBlockFound(
                        block_size * last_chunk_block_index,
                        block_size * last_chunk_block_index + remainder_chunk.len() as u64,
                    ));
                }
                let computed_value = knapsack_eval::<u64, N>(num, &self.knapsack.sequence);
                bytes.put_u64(computed_value);
            }
        }

        Ok(bytes.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use bytes::Bytes;
    use rand::SeedableRng;
    use test_case::test_case;

    #[test_case(
        "hell", 
        vec![0, 0, 152, 196, 72, 134, 12, 55, 0, 0, 0, 0, 0, 0, 0, 0];
        "32-bit aligned message with one block"
    )]
    #[test_case(
        "hel", 
        vec![0, 0, 152, 196, 71, 22, 27, 63];
        "non 32-bit aligned message with one block"
    )]
    #[test_case(
        "hello", 
        vec![0, 0, 152, 196, 72, 134, 12, 55, 0, 6, 123, 62, 0, 250, 19, 174];
        "non 32-bit aligned message with two blocks"
    )]
    fn test_merke_hellman_encrypt_ok(s: &str, expected: Vec<u8>) {
        let mut rng = rand::rngs::SmallRng::seed_from_u64(0);
        let mh = MerkleHellman::<32>::from_rng(&mut rng);
        let data = Bytes::from(s.to_owned());
        let encrypted = mh.pub_key.encrypt(&data).unwrap();
        assert_eq!(encrypted.to_vec(), expected);
    }
}
