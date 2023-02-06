use crate::knapsack::{
    MerkleHellmanError,
    SuperIncreasingKnapSack,
    MerkleHellmanPrivateKey,
    MerkleHellmanPublicKey,
    Result
};
use rand::{Rng, RngCore};
use crate::util::{
    gcd,
    modinverse,
    mul_mod
};


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleHellman<const N: usize> {
    pub pub_key: MerkleHellmanPublicKey<N>,
    pub(crate) priv_key: MerkleHellmanPrivateKey<N>,
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



#[cfg(test)]
mod tests {
    use crate::*;
    use test_case::test_case;
    use bytes::Bytes;
    use proptest::prelude::*;

    #[test]
    fn test_merkle_hellman_from_rng() {
        let mut rng = rand::thread_rng();
        let _ = MerkleHellman::<8>::from_rng(&mut rng);
    }
    #[test]
    fn test_default_merkle_hellman() {
        let mh = MerkleHellman::default();
        assert_eq!(mh.pub_key.knapsack.sequence.len(), 32);
        assert_eq!(mh.priv_key.knapsack.sequence.len(), 32);
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


    proptest! {

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