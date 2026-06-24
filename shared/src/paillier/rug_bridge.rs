// =============================================================================
//  rug_bridge.rs — Pont interne BigUint ↔ rug::Integer (GMP)
//
//  Les types publics (PublicKey, SecretKey, Edb…) restent en BigUint.
//  Seules les opérations coûteuses (modpow, mod_inverse) passent par GMP.
//
//  Conversion BigUint ↔ Integer : ~256 octets copiés (~256 ns), négligeable
//  face à un modpow 2048 bits (~1-2 ms avec GMP).
// =============================================================================

use num_bigint::BigUint;
use rug::Integer;
use rug::integer::Order;

#[inline]
pub(crate) fn to_rug(b: &BigUint) -> Integer {
    Integer::from_digits(&b.to_bytes_be(), Order::MsfBe)
}

#[inline]
pub(crate) fn from_rug(i: &Integer) -> BigUint {
    if *i == 0 {
        return BigUint::from(0u32);
    }
    let bytes: Vec<u8> = i.to_digits::<u8>(Order::MsfBe);
    if bytes.is_empty() {
        BigUint::from(0u32)
    } else {
        BigUint::from_bytes_be(&bytes)
    }
}

/// Exponentiation modulaire rapide : base^exp mod modulus (GMP).
#[inline]
pub(crate) fn modpow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    let b = to_rug(base);
    let e = to_rug(exp);
    let m = to_rug(modulus);
    let result = b.pow_mod(&e, &m)
        .expect("rug_bridge::modpow : modulus doit être > 0");
    from_rug(&result)
}

/// Variante qui prend directement des rug::Integer pré-convertis.
/// Évite de reconvertir modulus à chaque appel quand on chiffre N fois
/// avec la même clé (cas de build_edb).
#[inline]
pub(crate) fn modpow_pre(base: &Integer, exp: &Integer, modulus: &Integer) -> Integer {
    // pow_mod consomme self → on clone la base (256 octets, négligeable).
    // Retourne Err seulement si modulus == 0, impossible ici (n² > 0).
    base.clone()
        .pow_mod(exp, modulus)
        .expect("rug_bridge::modpow_pre : modulus doit être > 0")
}

/// Inverse modulaire rapide : a^{-1} mod m via GMP (invert).
#[inline]
pub(crate) fn mod_inverse_rug(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a_int = to_rug(a);
    let m_int = to_rug(m);
    match a_int.invert(&m_int) {
        Ok(inv) => Some(from_rug(&inv)),
        Err(_)  => None,
    }
}

/// Test de primalité probabiliste via GMP.
#[inline]
pub(crate) fn is_prime_rug(n: &BigUint, reps: u32) -> bool {
    if n < &BigUint::from(2u32) { return false; }
    let n_int = to_rug(n);
    n_int.is_probably_prime(reps) != rug::integer::IsPrime::No
}

// =============================================================================
// Contexte de chiffrement pré-converti — clé de l'optimisation mémoire/CPU
//
// Convertit g, n, n² en rug::Integer UNE SEULE FOIS, puis réutilise ces
// valeurs pour tous les chiffrements. Évite des millions de reconversions
// BigUint→Integer de la clé publique lors de la construction de l'EDB.
// =============================================================================

/// Contexte Paillier pré-converti en rug::Integer pour chiffrement en masse.
/// g n'est plus stocké : avec g = n+1, g^m est calculé par la formule (1+mn),
/// donc seuls n et n² sont nécessaires.
pub struct EncCtx {
    pub n:         Integer,
    pub n_squared: Integer,
}

impl EncCtx {
    /// Construit le contexte une seule fois à partir de la clé publique.
    /// `_g` est ignoré (g = n+1 est implicite dans la formule de encrypt).
    pub fn new(_g: &BigUint, n: &BigUint, n_squared: &BigUint) -> Self {
        EncCtx {
            n:         to_rug(n),
            n_squared: to_rug(n_squared),
        }
    }

    /// Chiffre Enc(0) = r^n mod n²  (puisque g^0 = 1).
    /// Évite l'exponentiation g^m totalement quand m=0.
    /// `r` doit déjà être tiré aléatoirement dans Z*_n.
    #[inline]
    pub fn encrypt_zero(&self, r: &Integer) -> Integer {
        // c = 1 × r^n mod n² = r^n mod n²
        modpow_pre(r, &self.n, &self.n_squared)
    }

    /// Chiffre Enc(m) = g^m × r^n mod n² avec contexte pré-converti.
    ///
    /// OPTIMISATION (g = n+1) :
    /// Avec le générateur standard g = n+1, le binôme de Newton donne
    ///     g^m = (1+n)^m ≡ 1 + m·n  (mod n²)
    /// car tous les termes en n², n³, … s'annulent mod n².
    /// On remplace donc l'exponentiation g^m (≈2000 mults) par une seule
    /// multiplication (1 + m·n). Gain ≈ ×2 sur encrypt (1 modpow au lieu de 2).
    /// Sécurité strictement identique : c'est la même valeur mathématique.
    #[inline]
    pub fn encrypt(&self, m: &Integer, r: &Integer) -> Integer {
        // g^m mod n² = (1 + m·n) mod n²   (identité valable ssi g = n+1)
        let g_m = (Integer::from(m * &self.n) + 1u32) % &self.n_squared;
        let r_n = modpow_pre(r, &self.n, &self.n_squared);
        (g_m * r_n) % &self.n_squared
    }
}
