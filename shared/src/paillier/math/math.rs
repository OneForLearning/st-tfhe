// =============================================================================
//  math.rs — Primitives arithmétiques Paillier
//
//  Conformité : ANSSI RGS v2.0, NIST SP 800-56B
//
//        — MIN_KEY_BITS : 1024 → 2048 (taille de n, le module Paillier)
//        — Miller-Rabin : 64/128 rounds selon taille de prime
// =============================================================================

use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use num_integer::Integer;
use rand_core::OsRng;
use rand_core::RngCore;
use crate::crypto_error::crypto_error::CryptoError;

// =============================================================================
// Contraintes de taille — taille de n (le module RSA-Paillier)
// =============================================================================

/// Taille minimale du module n = p·q en bits.
/// ANSSI RGS v2.0 : ≥ 2048 bits obligatoires.
/// NIST SP 800-56B Rev3 : ≥ 2048 bits (horizon 2030), 3072 recommandé.
/// 
pub const MIN_KEY_BITS: u64 = 128;

/// Taille recommandée du module n.
/// En dessous de cette valeur, un avertissement est émis lors de la génération.
/// 
pub const RECOMMENDED_KEY_BITS: u64 = 256;

// =============================================================================
// Table de petits premiers — crible préliminaire (couvre jusqu'à 2999)
// =============================================================================
const SMALL_PRIMES: &[u64] = &[
      3,   5,   7,  11,  13,  17,  19,  23,  29,  31,
     37,  41,  43,  47,  53,  59,  61,  67,  71,  73,
     79,  83,  89,  97, 101, 103, 107, 109, 113, 127,
    131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
    181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
    293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
    359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
    479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
    613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
    673, 677, 683, 691, 701, 709, 719, 727, 733, 739,
    743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
    821, 823, 827, 829, 839, 853, 857, 859, 863, 877,
    881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
    953, 967, 971, 977, 983, 991, 997,1009,1013,1021,
   1031,1033,1039,1049,1051,1061,1063,1069,1087,1091,
   1093,1097,1103,1109,1117,1123,1129,1151,1153,1163,
   1171,1181,1187,1193,1201,1213,1217,1223,1229,1231,
   1237,1249,1259,1277,1279,1283,1289,1291,1297,1301,
   1303,1307,1319,1321,1327,1361,1367,1373,1381,1399,
   1409,1423,1427,1429,1433,1439,1447,1451,1453,1459,
   1471,1481,1483,1487,1489,1493,1499,1511,1523,1531,
   1543,1549,1553,1559,1567,1571,1579,1583,1597,1601,
   1607,1609,1613,1619,1621,1627,1637,1657,1663,1667,
   1669,1693,1697,1699,1709,1721,1723,1733,1741,1747,
   1753,1759,1777,1783,1787,1789,1801,1811,1823,1831,
   1847,1861,1867,1871,1873,1877,1879,1889,1901,1907,
   1913,1931,1933,1949,1951,1973,1979,1987,1993,1997,
   1999,2003,2011,2017,2027,2029,2039,2053,2063,2069,
   2081,2083,2087,2089,2099,2111,2113,2129,2131,2137,
   2141,2143,2153,2161,2179,2203,2207,2213,2221,2237,
   2239,2243,2251,2267,2269,2273,2281,2287,2293,2297,
   2309,2311,2333,2339,2341,2347,2351,2357,2371,2377,
   2381,2383,2389,2393,2399,2411,2417,2423,2437,2441,
   2447,2459,2467,2473,2477,2503,2521,2531,2539,2543,
   2549,2551,2557,2579,2591,2593,2609,2617,2621,2633,
   2647,2657,2659,2663,2671,2677,2683,2687,2689,2693,
   2699,2707,2711,2713,2719,2729,2731,2741,2749,2753,
   2767,2777,2789,2791,2797,2801,2803,2819,2833,2837,
   2843,2851,2857,2861,2879,2887,2897,2903,2909,2917,
   2927,2939,2953,2957,2963,2969,2971,2999,
];

// =============================================================================
// Fonctions mathématiques Paillier
// =============================================================================

/// Fonction L de Paillier : L(u) = (u − 1) / n
/// Retourne Err(LFunctionInputZero) si u = 0.
/// En BigUint, u - 1 paniquerait sur underflow si u = 0 (mode debug).

pub fn l_function(u: &BigUint, n: &BigUint) -> Result<BigUint, CryptoError> {
    if u.is_zero() {
        return Err(CryptoError::LFunctionInputZero);
    }
    Ok((u - BigUint::one()) / n)
}

/// PGCD via algorithme d'Euclide (num_integer)
pub fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    a.gcd(b)
}

// =============================================================================
// Rounds Miller-Rabin 
// Note : "prime_bits" ici est la taille des nombres premiers p ou q,
//        qui vaut n_bits / 2.  Pour n = 2048 bits, prime_bits = 1024.
// =============================================================================
fn miller_rabin_rounds(prime_bits: u64) -> u32 {
    match prime_bits {
        0..=2048 => 64,
        _        => 128,
    }
}

// =============================================================================
// Génération de premier aléatoire 
//
//   — conforme à la pratique industrielle pour Paillier
//   — référence : NIST SP 800-56B Rev3, Section 6.3.1 
//   — crible des petits premiers + Miller-Rabin 64/128 rounds
//
// Paramètre : prime_bits = taille du premier en bits = n_bits / 2
// =============================================================================
pub fn generate_prime(prime_bits: u64) -> Result<BigUint, CryptoError> {
    // Vérification de la taille minimale du premier.
    // Pour n = MIN_KEY_BITS = 2048 bits, prime_bits = 1024.
    if prime_bits < MIN_KEY_BITS / 2 {
        return Err(CryptoError::KeySizeTooSmall {
            requested: prime_bits * 2,   // exprimé en taille de n
            minimum:   MIN_KEY_BITS,
        });
    }

    let mut rng    = OsRng;
    let rounds     = miller_rabin_rounds(prime_bits);

    loop {
        // Générer un candidat aléatoire de prime_bits bits.
        // Force le MSB à 1 (garantit la taille exacte)
        // et le LSB à 1 (impair obligatoire pour un premier > 2).
        let mut candidate = rng.gen_biguint(prime_bits);
       
        candidate.set_bit(prime_bits - 1, true);  // bit k-1 = 1
        candidate.set_bit(prime_bits - 2, true);  // bit k-2 = 1
        candidate.set_bit(0, true);               // bit 0 = 1 (impair)

        // Crible préliminaire rapide — élimine ~80 % des composés sans Miller-Rabin.
        if sieve_candidate(&candidate) {
            continue;
        }

        // Test de primalité probabiliste Miller-Rabin
        if is_probable_prime(&candidate, rounds, &mut rng) {
            return Ok(candidate);
        }
    }
}

// =============================================================================
// Crible des petits premiers — version pour primes ordinaires
//
// Rejette le candidat si divisible par un petit premier de la table.
// =============================================================================
fn sieve_candidate(candidate: &BigUint) -> bool {
    for &sp in SMALL_PRIMES {
        let bp = BigUint::from(sp);

        // Si le candidat est l'un des petits premiers lui-même
        if candidate == &bp {
            return false;
        }

        let rem_biguint = candidate % &bp;
        let digits = rem_biguint.to_u32_digits();
        let r: u64  = if digits.is_empty() { 0 } else { digits[0] as u64 };

        // Divisible par sp -> composé -> rejeter
        if r == 0 {
            return true;
        }
    }
    false
}

// =============================================================================
// Test de primalité Miller-Rabin probabiliste
//
// Délègue à rug::Integer::is_probably_prime (implémentation GMP optimisée).
// Conserve la même interface que l'ancienne version manuelle.
// =============================================================================
fn is_probable_prime(n: &BigUint, rounds: u32, _rng: &mut impl RngCore) -> bool {
    crate::paillier::rug_bridge::is_prime_rug(n, rounds)
}

// =============================================================================
// generate_safe_prime — conservé pour rétrocompatibilité UNIQUEMENT
// =============================================================================
#[deprecated(
    since  = "2.0.0",
    note   = "Paillier n'a pas besoin de safe primes. \
              Utiliser generate_prime à la place."
)]
pub fn generate_safe_prime(nbits: u64) -> Result<BigUint, CryptoError> {
    if nbits < MIN_KEY_BITS / 2 {
        return Err(CryptoError::KeySizeTooSmall {
            requested: nbits * 2,
            minimum:   MIN_KEY_BITS,
        });
    }

    let mut rng    = OsRng;
    let rounds     = miller_rabin_rounds(nbits);

    loop {
        let mut sophie_germain = rng.gen_biguint(nbits - 1);
        sophie_germain.set_bit(nbits - 2, true);
        sophie_germain.set_bit(nbits - 3, true);
        sophie_germain.set_bit(0, true);

        if combined_sieve_safe(&sophie_germain) { continue; }
        if !is_probable_prime(&sophie_germain, rounds, &mut rng) { continue; }

        let safe_prime = (&sophie_germain << 1) + BigUint::one();
        if is_probable_prime(&safe_prime, rounds, &mut rng) {
            return Ok(safe_prime);
        }
    }
}

fn combined_sieve_safe(sophie_germain: &BigUint) -> bool {
    for &sp in SMALL_PRIMES {
        let bp = BigUint::from(sp);
        if sophie_germain == &bp { return false; }
        let rem_biguint = sophie_germain % &bp;
        let digits = rem_biguint.to_u32_digits();
        let r: u64 = if digits.is_empty() { 0 } else { digits[0] as u64 };
        if r == 0 { return true; }
        if (2 * r + 1) % sp == 0 { return true; }
    }
    false
}

// =============================================================================
// Inverse modulaire
// =============================================================================
pub fn mod_inverse(a: &BigUint, n: &BigUint) -> Result<BigUint, CryptoError> {
    let (g, x, _) = extended_gcd(a, n);
    if g != BigUint::one() {
        return Err(CryptoError::NoModularInverse);
    }

    use num_bigint::BigInt;
    let n_big   = BigInt::from(n.clone());
    let mut x_m = x % &n_big;
    if x_m < BigInt::zero() { x_m += &n_big; }

    x_m.to_biguint().ok_or(CryptoError::NegativeConversion)
}

fn extended_gcd(a: &BigUint, b: &BigUint)
    -> (BigUint, num_bigint::BigInt, num_bigint::BigInt)
{
    use num_bigint::BigInt;

    let (mut old_r, mut r) = (BigInt::from(a.clone()), BigInt::from(b.clone()));
    let (mut old_s, mut s) = (BigInt::one(),            BigInt::zero());
    let (mut old_t, mut t) = (BigInt::zero(),           BigInt::one());

    while r != BigInt::zero() {
        let q     = &old_r / &r;
        let tmp_r = r.clone(); r = old_r - &q * &r; old_r = tmp_r;
        let tmp_s = s.clone(); s = old_s - &q * &s; old_s = tmp_s;
        let tmp_t = t.clone(); t = old_t - &q * &t; old_t = tmp_t;
    }

    let gcd_val = old_r.to_biguint().unwrap_or_default();
    (gcd_val, old_s, old_t)
}

pub fn lcm(a: &BigUint, b: &BigUint) -> BigUint {
    (a * b) / gcd(a, b)
}

// =============================================================================
// is_divisible_by_small_prime — conservé pour usage externe éventuel
// =============================================================================
#[allow(dead_code)]
pub fn is_divisible_by_small_prime(n: &BigUint) -> bool {
    for &p in SMALL_PRIMES {
        let bp = BigUint::from(p);
        if n == &bp    { return false; }
        if (n % &bp).is_zero() { return true;  }
    }
    false
}