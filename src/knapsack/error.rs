pub type Result<T> = std::result::Result<T, MerkleHellmanError>;
pub type Error = MerkleHellmanError;

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
