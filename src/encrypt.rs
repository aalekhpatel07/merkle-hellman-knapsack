use std::ops::BitAnd;

use crate::util::{gcd, modinverse, mul_mod, mul_mod_u64};
use bytes::{BufMut, Bytes, BytesMut};
use rand::prelude::*;
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum MerkleHellmanError {
    #[error(
        "The bytes {0} to {1} are null bytes and constitute a single block of plaintext. This is cryptographically insecure and therefore disallowed by this implementation."
    )]
    NullByteBlockFound(u64, u64),
    #[error("The block size must be at least 1 byte (i.e. 8).")]
    TooShortBlockSize,
    #[error("The block size must be one of 8, 16, or 32.")]
    InvalidBlockSize,
    #[error("The specified factor ({0}) is not invertible for the given modulus ({1}). Please choose a different modulus or a different factor.")]
    SpecifiedFactorIsNotInvertibleForGivenModulus(u64, u64),
    #[error("Found a partial block in ciphertext. This is malformed data. We operate on blocks of 64 bytes in the ciphertext.")]
    FoundAnImcompleteBlockInCiphertext,
    #[error("The ciphertext {0} is malformed and has no solution to the superincreasing knapsack problem.")]
    BadCipherText(u64),
}

pub type Result<T> = std::result::Result<T, MerkleHellmanError>;
pub type Error = MerkleHellmanError;

pub trait Encrypt {
    /// Ability to encrypts the given plaintext fallibly.
    fn encrypt(&self, data: &Bytes) -> Result<Bytes>;
}

pub trait Decrypt {
    /// Ability to decrypt the given ciphertext fallibly.
    fn decrypt(&self, data: &Bytes) -> Result<Bytes>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperIncreasingKnapSack {
    pub sequence: Vec<u64>,
    total: u64,
}

impl Default for SuperIncreasingKnapSack {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        Self::from_rng::<_, 32>(&mut rng)
    }
}

impl SuperIncreasingKnapSack {
    pub fn new(sequence: &[u64]) -> Self {
        Self {
            sequence: sequence.to_vec(),
            total: sequence.iter().sum::<u64>(),
        }
    }

    pub fn from_rng<R: RngCore, const N: usize>(rng: &mut R) -> Self {
        let mut sequence = [0u64; N];
        let mut sum: u64 = 0;

        for idx in 0..N {
            let next: u64 = rng.gen_range((sum + 1)..=((sum + 1) + (1 << 4)));
            sequence[idx] = next;
            sum += next;
        }

        Self {
            sequence: sequence.into(),
            total: sum,
        }
    }

    pub fn solve(&self, target: u64) -> Result<u64> {
        let mut remaining = target;
        let mut selection: u64 = 0;

        for (index, &value) in self.sequence.iter().rev().enumerate() {
            if remaining >= value {
                selection |= 1 << index;
                remaining -= value;
            }
        }

        if remaining != 0 {
            return Err(MerkleHellmanError::BadCipherText(
                target.try_into().unwrap(),
            ));
        }

        Ok(selection)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralKnapSack {
    pub sequence: Vec<u64>,
}

impl From<Vec<u64>> for GeneralKnapSack {
    fn from(sequence: Vec<u64>) -> Self {
        Self { sequence }
    }
}

fn knapsack_eval<S, const N: usize>(selection: S, sequence: &[u64]) -> u64
where
    S: BitAnd<u64, Output = u64> + Copy,
{
    (0..N)
        .filter_map(|i| {
            let is_bit_set = selection & (1 << i) != 0;
            if is_bit_set {
                Some(sequence[N - 1 - i])
            } else {
                None
            }
        })
        .sum()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleHellman<const N: usize> {
    pub pub_key: MerkleHellmanPublicKey<N>,
    priv_key: MerkleHellmanPrivateKey<N>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleHellmanPrivateKey<const N: usize> {
    pub knapsack: SuperIncreasingKnapSack,
    factor: u64,
    modulus: u64,
    factor_inverse: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleHellmanPublicKey<const N: usize> {
    knapsack: GeneralKnapSack,
}

impl<const N: usize> MerkleHellman<N> {
    pub fn new(sequence: &[u64; N], factor: u64, modulus: u64) -> Result<Self> {
        Self::from_superincreasing_knapsack(SuperIncreasingKnapSack::new(sequence), factor, modulus)
    }

    pub fn from_rng<R: RngCore>(rng: &mut R) -> Self {
        let si = SuperIncreasingKnapSack::from_rng::<_, 32>(rng);
        let modulus = rng.gen_range(si.total + 1..u64::MAX << 16);
        let factor = {
            let mut factor = rng.gen_range(2..=1 << 16);
            while gcd(factor, modulus) != 1 {
                factor = rng.gen_range(2..=1 << 16);
            }
            factor
        };

        let result = Self::from_superincreasing_knapsack(si, factor, modulus);
        if result.is_err() {
            println!("result: {:?}", result);
        }
        result.expect("generating a factor with a defined inverse for the given modulus explicitly")
    }

    pub fn from_superincreasing_knapsack(
        si: SuperIncreasingKnapSack,
        factor: u64,
        modulus: u64,
    ) -> Result<Self> {
        let general_knapsack = si
            .sequence
            .iter()
            .map(|&x| mul_mod(x, factor, modulus))
            .collect::<Vec<_>>()
            .into();

        let factor_inverse = modinverse(factor, modulus).ok_or(
            MerkleHellmanError::SpecifiedFactorIsNotInvertibleForGivenModulus(factor, modulus),
        )?;

        let private_key = MerkleHellmanPrivateKey {
            knapsack: si,
            factor,
            modulus,
            factor_inverse,
        };

        let public_key = MerkleHellmanPublicKey {
            knapsack: general_knapsack,
        };

        Ok(Self {
            pub_key: public_key,
            priv_key: private_key,
        })
    }
}

impl Default for MerkleHellman<32> {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        Self::from_rng(&mut rng)
    }
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

#[cfg(test)]
pub mod tests {

    use super::*;
    use proptest::prelude::*;
    use test_case::test_case;

    impl Arbitrary for SuperIncreasingKnapSack {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            let mut rng = rand::thread_rng();
            let si = Self::from_rng::<_, 32>(&mut rng);
            prop_oneof![Just(si)].boxed()
        }

        fn arbitrary() -> Self::Strategy {
            let mut rng = rand::thread_rng();
            let si = Self::from_rng::<_, 32>(&mut rng);
            prop_oneof![Just(si)].boxed()
        }
    }

    #[test]
    fn test_default_merkle_hellman() {
        let mh = MerkleHellman::default();
        assert_eq!(mh.pub_key.knapsack.sequence.len(), 32);
        assert_eq!(mh.priv_key.knapsack.sequence.len(), 32);
    }

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

    #[test_case(
        vec![0, 0, 4, 109, 60, 126, 45, 114, 0, 0, 0, 0, 0, 0, 0, 0], 8, 12;
        "32-bit aligned message with third and fourth block null but only third block is identified"
    )]
    #[test_case(
        vec![0, 0, 4, 109, 60, 126, 45, 114, 0, 0, 0, 0, 0, 0, 4, 109], 8, 12;
        "32-bit aligned message with third but middle block null"
    )]
    #[test_case(
        vec![0, 0, 4, 109, 60, 126, 45, 114, 0, 0, 0, 0], 8, 12;
        "32-bit aligned message with third and last block null"
    )]
    #[test_case(
        vec![0, 0, 0, 0], 0, 4;
        "32-bit aligned message with one block"
    )]
    fn test_merkel_hellman_encrypt_err_null_block(v: Vec<u8>, error_start: u64, error_end: u64) {
        let mut rng = rand::rngs::SmallRng::seed_from_u64(0);
        let mh = MerkleHellman::<32>::from_rng(&mut rng);
        let data = Bytes::from(v);
        let encrypted = mh.pub_key.encrypt(&data);
        assert!(encrypted.is_err());

        match encrypted.unwrap_err() {
            Error::NullByteBlockFound(start, end) => {
                assert_eq!(start, error_start);
                assert_eq!(end, error_end);
            }
            _ => panic!("Unexpected error"),
        }
    }

    #[test]
    fn test_merkle_hellman_from_rng() {
        let mut rng = rand::thread_rng();
        let _ = MerkleHellman::<8>::from_rng(&mut rng);
    }

    #[test_case(vec![150], 548; "single 150")]
    #[test_case(vec![1], 471; "single 1")]
    /// This is the encryption example from [Lattice Reduction Attack on the Knapsack]
    /// [1]: http://www.cs.sjsu.edu/faculty/stamp/papers/topics/topic16/Knapsack.pdf
    fn test_merkle_hellman_from_knapsack(data: Vec<u8>, ciphertext: u64) {
        let mh = MerkleHellman::new(&[2, 3, 7, 14, 30, 57, 120, 251], 41, 491).unwrap();
        let data = Bytes::from(data);
        let encrypted = mh.encrypt(&data).unwrap().to_vec();
        let (first, _) = encrypted.split_at(8);

        let mut dst = [0u8; 8];
        dst.copy_from_slice(first);

        assert_eq!(ciphertext, u64::from_be_bytes(dst));
        let decrypted = mh.decrypt(&Bytes::from(encrypted)).unwrap();
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_superincreasing_knapsack() {
        let mut rng = rand::thread_rng();
        let si = SuperIncreasingKnapSack::from_rng::<_, 32>(&mut rng);
        for i in 0..si.sequence.len() {
            let mut sum = 0;
            for j in 0..i {
                sum += si.sequence[j];
            }
            assert!(si.sequence[i] > sum);
        }
    }

    #[test_case(vec![0]; "single 0")]
    fn test_encrypt_and_decrypt(data: Vec<u8>) {
        let mut rng = rand::thread_rng();
        let mh = MerkleHellman::<32>::from_rng(&mut rng);
        let data = Bytes::from(data);
        assert_eq!(mh.encrypt(&data), Err(Error::NullByteBlockFound(0, 1)));
    }

    proptest! {

        #[test]
        fn test_superincreasing_knapsack_prop(si in any::<SuperIncreasingKnapSack>()) {
            for i in 0..si.sequence.len() {
                let mut sum = 0;
                for j in 0..i {
                    sum += si.sequence[j];
                }
                assert!(si.sequence[i] > sum);
            }
        }

        #[test]
        fn test_encrypt_with_example_mh(
            data in any::<Vec<u8>>(),
        ) {
            // Because block-size is 1, we can't encrypt a null byte.
            if !data.contains(&0) {
                let mh = MerkleHellman::new(
                    &[2, 3, 7, 14, 30, 57, 120, 251],
                    41,
                    491
                ).unwrap();

                let Ok(encrypted) = mh.encrypt(&Bytes::from(data.clone())) else {
                    panic!("Encryption failed");
                };
                let decrypted = mh.decrypt(&encrypted).unwrap();
                prop_assert_eq!(data, decrypted.to_vec());
            }
        }

        #[test]
        fn test_encrypt_decrypt_works_okay(
            data in any::<Vec<u8>>(),
        ) {

            let mut rng = rand::thread_rng();
            let mh = MerkleHellman::<32>::from_rng(&mut rng);

            for chunk in data.chunks_exact(4) {
                let raw = Bytes::from(chunk.to_vec());
                if chunk.iter().all(|&x| x == 0) {
                    prop_assert!(mh.encrypt(&raw).is_err());
                } else {
                    let obtained: [u8; 4] = mh.decrypt(&mh.encrypt(&raw).expect("Should encrypt alright")).expect("Should decrypt alright").to_vec().try_into().expect("Should fit in 4 bytes");
                    prop_assert_eq!(
                        u32::from_le_bytes(raw.to_vec().try_into().unwrap()),
                        u32::from_be_bytes(obtained)
                    );
                }
            }
        }
    }
}
