use crate::knapsack::{
    SuperIncreasingKnapSack,
    GeneralKnapSack
};



#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleHellmanPrivateKey<const N: usize> {
    pub knapsack: SuperIncreasingKnapSack,
    pub factor: u64,
    pub modulus: u64,
    pub factor_inverse: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleHellmanPublicKey<const N: usize> {
    pub knapsack: GeneralKnapSack,
}


#[cfg(test)]
mod tests {
    use test_case::test_case;
    use bytes::Bytes;
    use crate::*;

    #[test_case(vec![0]; "single 0")]
    fn test_encrypt_and_decrypt(data: Vec<u8>) {
        let mut rng = rand::thread_rng();
        let mh = MerkleHellman::<32>::from_rng(&mut rng);
        let data = Bytes::from(data);
        assert_eq!(mh.encrypt(&data), Err(Error::NullByteBlockFound(0, 1)));
    }
}