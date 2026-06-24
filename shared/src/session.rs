// ─────────────────────────────────────────────────────────────────────────────
// shared/src/session.rs — Gestion des sessions isolées
//
// Séparation physique des fichiers par rôle :
//
//   h1/output/<session_id>/
//     ├── pk_pseudo.json          — clé publique (partagée avec le serveur)
//     ├── patients_chiffres.csv   — PII chiffrés (envoyé au serveur)
//     └── intersection_results.csv — résultat PSI (H1 uniquement)
//
//   server/output/<session_id>/
//     └── patients_pseudonymises.csv — pseudonymes finaux (serveur uniquement)
//
// Aucun chemin hardcodé dans le code métier.
// ─────────────────────────────────────────────────────────────────────────────

use std::time::{SystemTime, UNIX_EPOCH};
use std::fs;

/// Génère un session_id unique : timestamp microseconde (8 hex) + nonce (4 hex).
pub fn generate_session_id() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_micros();
    let nonce: u32 = {
        use rand::RngCore;
        rand::rngs::OsRng.next_u32()
    };
    format!("{:08x}{:04x}", ts, nonce & 0xFFFF)
}

/// Chemins côté H1 pour une session.
#[derive(Debug, Clone)]
pub struct H1SessionPaths {
    pub session_id:      String,
    /// h1/output/<session_id>/
    pub output_dir:      String,
    /// h1/output/<session_id>/pk_pseudo.json
    pub pk_pseudo:       String,
    /// h1/output/<session_id>/patients_chiffres.csv
    pub csv_chiffres:    String,
    /// h1/output/<session_id>/intersection_results.csv
    pub csv_intersection: String,
}

impl H1SessionPaths {
    pub fn new() -> Self { Self::from_id(generate_session_id()) }

    pub fn from_id(session_id: String) -> Self {
        let output_dir      = format!("h1/output/{}", session_id);
        let pk_pseudo        = format!("{}/pk_pseudo.json", output_dir);
        let csv_chiffres     = format!("{}/patients_chiffres.csv", output_dir);
        let csv_intersection = format!("{}/intersection_results.csv", output_dir);
        H1SessionPaths { session_id, output_dir, pk_pseudo,
                         csv_chiffres, csv_intersection }
    }

    pub fn create_dirs(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.output_dir)
    }

    /// Écrit le session_id dans un fichier sentinelle lisible par le serveur.
    pub fn write_session_file(&self) -> std::io::Result<()> {
        fs::write(format!("{}/session_id.txt", self.output_dir), &self.session_id)
    }
}

/// Chemins côté Serveur pour une session.
#[derive(Debug, Clone)]
pub struct ServerSessionPaths {
    pub session_id:    String,
    /// server/output/<session_id>/
    pub output_dir:    String,
    /// server/output/<session_id>/patients_pseudonymises.csv
    pub csv_pseudo_out: String,
    /// Chemin vers le CSV chiffré produit par H1 (pour lecture par le serveur)
    pub csv_chiffres_h1: String,
    /// Chemin vers la pk produite par H1 (pour lecture par le serveur)
    pub pk_pseudo_h1: String,
}

impl ServerSessionPaths {
    pub fn from_id(session_id: String) -> Self {
        let output_dir      = format!("server/output/{}", session_id);
        let csv_pseudo_out   = format!("{}/patients_pseudonymises.csv", output_dir);
        // Le serveur lit les fichiers produits par H1
        let csv_chiffres_h1  = format!("h1/output/{}/patients_chiffres.csv", session_id);
        let pk_pseudo_h1     = format!("h1/output/{}/pk_pseudo.json", session_id);
        ServerSessionPaths { session_id, output_dir, csv_pseudo_out,
                             csv_chiffres_h1, pk_pseudo_h1 }
    }

    pub fn create_dirs(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.output_dir)
    }
}

/// Scanne h1/output/ et retourne le session_id le plus récent.
pub fn find_latest_session() -> Option<String> {
    let dir = std::path::Path::new("h1/output");
    if !dir.exists() { return None; }

    let mut entries: Vec<(std::time::SystemTime, String)> =
        std::fs::read_dir(dir).ok()?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter_map(|e| {
                let modified = e.metadata().ok()?.modified().ok()?;
                let name = e.file_name().to_string_lossy().to_string();
                Some((modified, name))
            })
            .collect();

    entries.sort_by(|a, b| b.0.cmp(&a.0));
    entries.into_iter().next().map(|(_, name)| name)
}

// Alias pour la compatibilité avec le code existant qui utilise SessionPaths
pub type SessionPaths = H1SessionPaths;
