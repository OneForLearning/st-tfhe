// ============================================================================
//  lib.rs — dpeg_shared
//
//  Bibliothèque commune au protocole DPEG, utilisée par les deux rôles :
//    - node    (hôpital : génère pk/sk + déchiffre s'il est initiateur,
//               chiffre sa base s'il est participant)
//    - server  (calculs homomorphes uniquement)
//
//  Contient toutes les primitives, types et utilitaires partagés.
//  AUCUNE couche de transport (pas de TCP, pas de sockets) : la sérialisation
//  transport-agnostique vit dans `codec`, le réseau est à la charge du backend.
// ============================================================================

pub mod crypto_error;
pub mod paillier;
pub mod paillier_kea;
pub mod exactmatch;
pub mod key_management;
pub mod karatsuba_mul;
pub mod codec;
pub mod validation;

// ── Re-exports les plus couramment utilisés ──────────────────────────────────
pub use crate::paillier::math;
pub use crate::paillier::p_keygen;
pub use crate::paillier::p_encrypt;
pub use crate::paillier::p_decrypt;

pub use crate::paillier::math::{l_function, gcd, generate_prime, mod_inverse, lcm};
pub use p_keygen::p_keygen::{SecretKey, KeyPair};
pub use crypto_error::crypto_error::CryptoError;
pub use key_management::{KeyRegistry, RegistryError};
pub mod session;
pub use session::{
    H1SessionPaths, ServerSessionPaths,
    SessionPaths, generate_session_id, find_latest_session,
};
pub mod config;
pub use config::{DpegConfig, parse_cli_args};
