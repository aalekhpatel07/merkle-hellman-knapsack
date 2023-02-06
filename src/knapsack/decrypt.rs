use crate::knapsack::{
    Result,
    MerkleHellman,
    Error,
};
use bytes::{Bytes, BytesMut, BufMut};
use crate::util::mul_mod_u64;

pub trait Decrypt {
    /// Ability to decrypt the given ciphertext fallibly.
    fn decrypt(&self, data: &Bytes) -> Result<Bytes>;
}


impl<const N: usize> Decrypt for MerkleHellman<N> {
    fn decrypt(&self, data: &Bytes) -> Result<Bytes> {
        let chunks = data.chunks_exact(8);
        let chunks_len = chunks.len();
        let remainder = chunks.remainder();

        if !remainder.is_empty() {
            return Err(Error::FoundAnImcompleteBlockInCiphertext);
        }

        let mut messages = BytesMut::new();
        let block_size = (N / 8) as u64;

        for (idx, num) in chunks.enumerate() {
            let dst: [u8; 8] = num.try_into().unwrap();
            let num = u64::from_be_bytes(dst);
            if num == 0 {
                if idx != chunks_len - 1 {
                    return Err(Error::NullByteBlockFound(
                        idx as u64 * block_size,
                        (idx as u64 + 1) * block_size,
                    ));
                }
                break;
            }

            let num = mul_mod_u64(num, self.priv_key.factor_inverse, self.priv_key.modulus);

            match N {
                8 => {
                    let knapsack_solution = self.priv_key.knapsack.solve(num)?;
                    messages.put_u8(knapsack_solution as u8);
                }
                16 => {
                    let knapsack_solution = self.priv_key.knapsack.solve(num)?;
                    messages.put_u16(knapsack_solution as u16);
                }
                32 => {
                    let knapsack_solution = self.priv_key.knapsack.solve(num)?;
                    messages.put_u32(knapsack_solution as u32);
                }
                _ => {}
            }
        }
        Ok(messages.into())
    }
}