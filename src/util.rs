


/// Compute the extendend greatest common divisor of two numbers
/// using the [extended Euclidean algorithm].
/// 
/// *Note*: 
/// I didn't want a dependency for two functions so I just copied them
/// from the [modinverse] crate and monomorphized them for isize/usize.
/// 
/// [modinverse]: https://docs.rs/modinverse/latest/src/modinverse/lib.rs.html#60-68
/// [extended Euclidean algorithm]: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
pub fn egcd(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        (b, 0, 1)
    }
    else {
        let (g, x, y) = egcd(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

/// Calculates the [modular multiplicative
/// inverse] *x*
/// of an integer *a* such that *ax* ≡ 1 (mod *m*).
///
/// Such an integer may not exist. If so, this function will return `None`.
/// Otherwise, the inverse will be returned wrapped up in a `Some`.
/// 
/// *Note*: 
/// I didn't want a dependency for two functions so I just copied them
/// from the [modinverse] crate and monomorphized them for usize.
/// 
/// [modinverse]: https://docs.rs/modinverse/latest/src/modinverse/lib.rs.html#60-68
/// [modular multiplicative inverse]: https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
pub fn modinverse(a: u64, m: u64) -> Option<u64> {
    let ai = a as i128;
    let mi = m as i128;
    let (g, x, _) = egcd(ai, mi);
    let g = g.rem_euclid(mi) as u64;

    match g {
        1 => Some((x % mi).rem_euclid(mi) as u64),
        _ => {
            println!("modinverse: {} and {} are not coprime, g: {}, x: {}", a, m, g, x);
            None
        },
    }
}



/// I just want to multiply and reduce modulo in one step
/// without overflowing. See [Julian's answer] on SO.
/// 
/// [Julian's Answer]: https://stackoverflow.com/a/66722460/14045826
#[inline(always)]
pub fn mul_mod(x: u64, y: u64, m: u64) -> u64 {
    let (a, b, c) = (x as u128, y as u128, m as u128);
    ((a * b) % c) as u64
}

#[inline(always)]
pub fn mul_mod_u64(x: u64, y: u64, m: u64) -> u64 {
    let (a, b, c) = (x as u128, y as u128, m as u128);
    ((a * b) % c) as u64
}

#[inline(always)]
pub fn gcd(a: u64, b: u64) -> u64 {
    match b == 0 {
        true => a,
        false => gcd(b, a % b),
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;
    use test_case::test_case;


    #[test_case(4, 2058270774454069813; "no subtract overflow panic")]
    fn test_egcd_unit(
        a: usize, 
        b: usize
    ) {
        let (g, _x, _y) = egcd(a as i128, b as i128);
        assert!((b as i128) % g == 0);
        assert!((a as i128) % g == 0);
    }

    #[test]
    fn foo() {
        let x = 2usize;
        let _y: i128 = i128::try_from(x).unwrap();
    }

    proptest! {
        #[test]
        fn test_modular_inverse(
            a: u64, 
            m: u64
        ) {
            if let Some(inv) = modinverse(a, m) {
                prop_assert_eq!(mul_mod(a, inv, m), 1);
            }
        }
        #[test]
        fn test_egcd(
            a: i128, 
            b: i128
        ) {
            let (g, _, _) = egcd(a, b);
            prop_assert!(b % g == 0);
            prop_assert!(a % g == 0);
        }

    }
}