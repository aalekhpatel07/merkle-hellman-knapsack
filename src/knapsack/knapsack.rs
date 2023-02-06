use core::ops::BitAnd;
use rand::{RngCore, Rng};
use crate::knapsack::{MerkleHellmanError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperIncreasingKnapSack {
    pub sequence: Vec<u64>,
    pub total: u64,
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

pub fn knapsack_eval<S, const N: usize>(selection: S, sequence: &[u64]) -> u64
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


#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use crate::*;


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
    }
}