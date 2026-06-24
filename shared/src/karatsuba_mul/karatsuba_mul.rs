use num_bigint::BigUint;
use num_traits::Zero;
use crate::crypto_error::crypto_error::CryptoError;
pub use crate::paillier::math::{l_function, gcd, generate_prime, mod_inverse, lcm};

// Multiplication Rapide pour l'optimisation des calculs utilisant la multiplication de manière homomorphe

// ---------------------------------------------------------------------------
pub fn fast_mul(
    a:       &BigUint,
    b:       &BigUint,
    modulus: &BigUint,
) -> Result<BigUint, CryptoError> {
    if modulus.is_zero() {
        return Err(CryptoError::InvalidInput(
            "multiple_precision_mul : modulus ne peut pas être zéro".into(),
        ));
    }
    Ok(karatsuba_mul(a, b, modulus))
}

// ---------------------------------------------------------------------------
// karatsuba_mul
// ---------------------------------------------------------------------------
pub fn karatsuba_mul(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    let a_bits = a.bits();
    let b_bits = b.bits();

    // Cas de base : multiplication directe pour les petits opérandes
    if a_bits < 512 || b_bits < 512 {
        return (a * b) % n;
    }

    // k = moitié de la longueur du plus grand opérande (en bits)

    let k = std::cmp::max(a_bits, b_bits) / 2;

    // base = 2^k, mask = 2^k - 1

    let base = BigUint::from(1u32) << k;
    let mask = &base - BigUint::from(1u32);

    // Décomposition : x = x_high * 2^k + x_low

    let a_low  = a & &mask;
    let a_high = a >> k;
    let b_low  = b & &mask;
    let b_high = b >> k;

    // Trois produits récursifs — SANS réduction intermédiaire
    
    let z0      = karatsuba_mul(&a_low,               &b_low,               n);
    let z2      = karatsuba_mul(&a_high,              &b_high,              n);
    let z1_full = karatsuba_mul(&(&a_low + &a_high),  &(&b_low + &b_high),  n);

    // z1 = z1_full - z0 - z2   (mod n)
    // On ajoute 2n avant les soustractions pour rester positif.

    let z1 = (z1_full + n + n - &z0 - &z2) % n;

    // Reconstruction : (z2 << 2k) + (z1 << k) + z0   (mod n)
    
    /* Les décalages sont réduits mod n immédiatement pour éviter
    une explosion de la taille mémoire.*/

    let part2 = (&z2 << (2 * k)) % n;
    let part1 = (&z1 << k) % n;

    (part2 + part1 + z0) % n
}

