// ─────────────────────────────────────────────────────────────────────────────
// shared/src/config.rs — Configuration runtime du protocole DPEG
//
// Priorité (de la plus haute à la plus basse) :
//   1. Arguments CLI   : --csv-h1 mon_fichier.csv
//   2. Variables d'env : DPEG_CSV_H1=mon_fichier.csv
//   3. Fichier dpeg.toml à la racine du workspace
//   4. Valeurs par défaut intégrées
//
// Aucun chemin n'est hardcodé dans le code métier.
// Tous les chemins passent par DpegConfig.
// ─────────────────────────────────────────────────────────────────────────────

use std::collections::HashMap;
use std::fs;
use std::env;

/// Configuration complète d'une session DPEG.
#[derive(Debug, Clone)]
pub struct DpegConfig {
    /// Fichier CSV de la base patients H1 (pour le PSI)
    pub csv_h1: String,
    /// Fichier CSV de la base patients H2 (pour le PSI)
    pub csv_h2: String,
    /// Fichier CSV d'entrée pour la pseudonymisation
    pub csv_pseudo_input: String,
    /// Taille de clé Paillier en bits
    pub key_bits: u64,
    /// Facteur de charge β pour le PSI (réel, >= 0.1)
    pub beta: f64,
    /// Nombre de bins pour le PSI binné (0 ou 1 = PSI classique)
    pub num_bins: usize,
}

impl Default for DpegConfig {
    fn default() -> Self {
        DpegConfig {
            csv_h1:           "hopital_A.csv".to_string(),
            csv_h2:           "hopital_B.csv".to_string(),
            csv_pseudo_input: "patients_input.csv".to_string(),
            key_bits:         2048,
            beta:             1.0,
            num_bins:         0,
        }
    }
}

impl DpegConfig {
    /// Charge la configuration en respectant la priorité :
    /// CLI > env > dpeg.toml > défauts.
    ///
    /// `cli_args` : paires clé=valeur issues de la ligne de commande.
    /// Exemple : vec![("csv-h1", "mon_h1.csv"), ("key-bits", "512")]
    pub fn load(cli_args: &[(&str, &str)]) -> Self {
        let mut cfg = DpegConfig::default();

        // 3. Fichier dpeg.toml (si présent)
        if let Ok(content) = fs::read_to_string("dpeg.toml") {
            cfg.apply_toml(&content);
        }

        // 2. Variables d'environnement
        cfg.apply_env();

        // 1. Arguments CLI (priorité maximale)
        for (key, value) in cli_args {
            cfg.apply_kv(key, value);
        }

        cfg
    }

    /// Applique un fichier TOML minimal (format clé = "valeur").
    fn apply_toml(&mut self, content: &str) {
        let pairs = parse_simple_toml(content);
        for (k, v) in &pairs {
            self.apply_kv(k, v);
        }
    }

    /// Applique les variables d'environnement DPEG_*.
    fn apply_env(&mut self) {
        let mapping = [
            ("DPEG_CSV_H1",           "csv-h1"),
            ("DPEG_CSV_H2",           "csv-h2"),
            ("DPEG_CSV_PSEUDO_INPUT", "csv-pseudo-input"),
            ("DPEG_KEY_BITS",         "key-bits"),
            ("DPEG_BETA",             "beta"),
            ("DPEG_NUM_BINS",         "bins"),
        ];
        for (env_key, cfg_key) in &mapping {
            if let Ok(val) = env::var(env_key) {
                self.apply_kv(cfg_key, &val);
            }
        }
    }

    /// Applique une paire clé/valeur sur la config.
    fn apply_kv(&mut self, key: &str, value: &str) {
        match key {
            "csv-h1"           | "csv_h1"           => self.csv_h1           = value.to_string(),
            "csv-h2"           | "csv_h2"           => self.csv_h2           = value.to_string(),
            "csv-pseudo-input" | "csv_pseudo_input" => self.csv_pseudo_input = value.to_string(),
            "key-bits"         | "key_bits"         => {
                if let Ok(v) = value.parse() { self.key_bits = v; }
            }
            "beta" => {
                if let Ok(v) = value.parse::<f64>() { self.beta = v; }
            }
            "bins" | "num-bins" | "num_bins" => {
                if let Ok(v) = value.parse() { self.num_bins = v; }
            }
            _ => {} // clé inconnue ignorée silencieusement
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Parseur TOML minimal — supporte uniquement clé = "valeur" et clé = 1234
// Pas de dépendance externe.
// ─────────────────────────────────────────────────────────────────────────────
fn parse_simple_toml(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('[') || line.is_empty() {
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key   = line[..eq].trim().to_string();
            let value = line[eq + 1..].trim()
                .trim_matches('"')
                .to_string();
            map.insert(key, value);
        }
    }
    map
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_cli_args — extrait les paires --clé valeur depuis env::args()
//
// Accepte :
//   --csv-h1 mon_fichier.csv
//   --key-bits 512
//   pseudo              (mot-clé de mode, ignoré ici)
//   mon_fichier.csv     (argument positionnel, ignoré ici)
// ─────────────────────────────────────────────────────────────────────────────
pub fn parse_cli_args() -> Vec<(String, String)> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut pairs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            let key = args[i][2..].to_string();
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                pairs.push((key, args[i + 1].clone()));
                i += 2;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    pairs
}
