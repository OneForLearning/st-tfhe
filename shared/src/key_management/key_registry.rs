// ============================================================================
// KeyRegistry — Registre de clés Paillier thread-safe
//
// Gère uniquement les clés Paillier (pk, sk).
// Les clés KEA sont spécifiques au Serveur et gérées dans server/src/.
//
// Arc<RwLock<Option<T>>> :
//   - Arc<T>    : partageable entre threads
//   - RwLock<T> : plusieurs lecteurs simultanés, un seul écrivain exclusif
//   - Option<T> : distingue "clé non chargée" de "clé chargée"
// ============================================================================

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use crate::paillier::p_keygen::p_keygen::{PublicKey, SecretKey, KeyPair};
use crate::crypto_error::crypto_error::CryptoError;

// ── Erreurs du registre ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum RegistryError {
    /// Aucune clé Paillier chargée dans le registre
    NoPaillierKey,
    /// Le verrou RwLock est empoisonné (thread paniqué en zone critique)
    LockPoisoned,
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::NoPaillierKey =>
                write!(f, "Aucune clé Paillier chargée dans le registre"),
            RegistryError::LockPoisoned =>
                write!(f, "Verrou du registre empoisonné — redémarrage requis"),
        }
    }
}

impl std::error::Error for RegistryError {}

impl From<RegistryError> for CryptoError {
    fn from(e: RegistryError) -> Self {
        CryptoError::RegistryError(e.to_string())
    }
}

// ── État interne ─────────────────────────────────────────────────────────────

struct RegistryState {
    keypair: Option<KeyPair>,
}

// ── KeyRegistry ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct KeyRegistry {
    inner: Arc<RwLock<RegistryState>>,
}

impl KeyRegistry {
    pub fn new() -> Self {
        KeyRegistry {
            inner: Arc::new(RwLock::new(RegistryState { keypair: None })),
        }
    }

    fn write(&self) -> Result<RwLockWriteGuard<'_, RegistryState>, RegistryError> {
        self.inner.write().map_err(|_| RegistryError::LockPoisoned)
    }

    fn read(&self) -> Result<RwLockReadGuard<'_, RegistryState>, RegistryError> {
        self.inner.read().map_err(|_| RegistryError::LockPoisoned)
    }

    /// Charge ou remplace la paire de clés Paillier.
    pub fn set_keypair(&self, kp: KeyPair) -> Result<(), RegistryError> {
        self.write()?.keypair = Some(kp);
        Ok(())
    }

    /// Supprime la clé Paillier (déclenche la zeroization via Drop).
    pub fn clear_keypair(&self) -> Result<(), RegistryError> {
        self.write()?.keypair = None;
        Ok(())
    }

    /// Retourne un clone de la clé publique (pk est publique, clonage sûr).
    pub fn public_key(&self) -> Result<PublicKey, RegistryError> {
        self.read()?
            .keypair
            .as_ref()
            .map(|kp| kp.public_key.clone())
            .ok_or(RegistryError::NoPaillierKey)
    }

    /// Exécute une opération avec référence à sk sans jamais la cloner.
    /// sk reste sous contrôle du registre — ne fuite jamais dans le heap.
    pub fn with_secret_key<F, T>(&self, f: F) -> Result<T, RegistryError>
    where
        F: FnOnce(&SecretKey) -> T,
    {
        self.read()?
            .keypair
            .as_ref()
            .map(|kp| f(&kp.secret_key))
            .ok_or(RegistryError::NoPaillierKey)
    }

    /// Vérifie si une paire de clés est chargée.
    pub fn has_keypair(&self) -> bool {
        self.read().ok()
            .and_then(|g| g.keypair.as_ref().map(|_| true))
            .unwrap_or(false)
    }
}

impl Default for KeyRegistry {
    fn default() -> Self { Self::new() }
}
