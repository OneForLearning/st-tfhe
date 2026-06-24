// ============================================================================
//  shared/src/exactmatch/canonical.rs — Normalisation canonique + clé de match
//
//  RÈGLE D'OR : pour que le PSI trouve les patients communs, TOUS les hôpitaux
//  (H1…H10) doivent produire EXACTEMENT la même clé pour le même patient. Cette
//  normalisation est donc l'unique source de vérité, partagée par tous via
//  `dpeg_shared`. Ne jamais la diverger d'un hôpital à l'autre.
//
//  Pipeline d'un patient → clé :
//    (prénom, nom, date_naissance, NSS)
//      → normalisation de chaque champ (accents, casse, séparateurs)
//      → composite canonique "NSS|YYYYMMDD|nom|prenom"
//      → SHA-256 → [u8; 32]  (MatchKey)
//
//  La taille fixe (32 o) est garantie par le hachage, quelle que soit la
//  longueur des noms. Le composite sensible est zeroisé après hachage.
// ============================================================================

use sha2::{Sha256, Digest};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use crate::crypto_error::crypto_error::CryptoError;
use super::types::MatchKey;

/// Marque de combinaison (diacritique) à retirer après décomposition NFD.
/// Couvre les blocs Unicode des diacritiques courants (suffisant pour le
/// français : é è ê ë à â ä î ï ô ö ù û ü ÿ ç ñ …).
fn is_combining(c: char) -> bool {
    matches!(c as u32,
        0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF |
        0x20D0..=0x20FF | 0xFE20..=0xFE2F)
}

/// Normalise un nom/prénom : retire accents, met en minuscule, ne conserve
/// que les caractères alphanumériques ASCII.
///
/// Conséquence voulue : « Jean-Pierre », « Jean Pierre » et « JeanPierre »
/// donnent tous « jeanpierre » ; « François » et « FRANCOIS » donnent
/// « francois » ; « O'Brien » donne « obrien ».
pub fn normalize_name(s: &str) -> String {
    s.nfd()
        .filter(|c| !is_combining(*c))      // retire les diacritiques
        .flat_map(|c| c.to_lowercase())     // minuscule
        .filter(|c| c.is_ascii_alphanumeric()) // garde [a-z0-9], retire - _ ' . espace
        .collect()
}

/// Normalise une date de naissance vers le format canonique `YYYYMMDD`.
///
/// Accepte les séparateurs courants (`/ - . espace`) et les ordres
/// JJ?MM?AAAA ou AAAA?MM?JJ. Exemples acceptés :
///   "01/02/1990", "1990-02-01", "01.02.1990", "1990/02/01", "01021990".
pub fn normalize_date(s: &str) -> Result<String, CryptoError> {
    // Découpe en groupes de chiffres (ignore tout séparateur).
    let groups: Vec<String> = s
        .split(|c: char| !c.is_ascii_digit())
        .filter(|g| !g.is_empty())
        .map(|g| g.to_string())
        .collect();

    let (y, m, d): (u32, u32, u32) = match groups.as_slice() {
        // 3 groupes : déterminer l'année par le groupe à 4 chiffres.
        [a, b, c] => {
            if a.len() == 4 {
                (a.parse().unwrap_or(0), b.parse().unwrap_or(0), c.parse().unwrap_or(0))
            } else {
                (c.parse().unwrap_or(0), b.parse().unwrap_or(0), a.parse().unwrap_or(0))
            }
        }
        // 1 groupe de 8 chiffres : AAAAMMJJ si l'année est plausible, sinon JJMMAAAA.
        [g] if g.len() == 8 => {
            let first4: u32 = g[0..4].parse().unwrap_or(0);
            if (1900..=2155).contains(&first4) {
                (first4, g[4..6].parse().unwrap_or(0), g[6..8].parse().unwrap_or(0))
            } else {
                (g[4..8].parse().unwrap_or(0), g[2..4].parse().unwrap_or(0), g[0..2].parse().unwrap_or(0))
            }
        }
        _ => return Err(CryptoError::InvalidInput(
            format!("date de naissance non reconnue : '{s}'"))),
    };

    if !(1900..=2155).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(CryptoError::InvalidInput(
            format!("date de naissance hors plage : '{s}' → {y}-{m}-{d}")));
    }
    Ok(format!("{y:04}{m:02}{d:02}"))
}

/// Normalise un NSS : ne conserve que les chiffres, valide la longueur (13 ou 15).
pub fn normalize_nss(s: &str) -> Result<String, CryptoError> {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() == 13 || digits.len() == 15 {
        Ok(digits)
    } else {
        Err(CryptoError::InvalidInput(
            format!("NSS invalide (longueur {}, attendu 13 ou 15) : '{s}'", digits.len())))
    }
}

/// Construit le composite canonique `NSS|YYYYMMDD|nom|prenom` (champs normalisés).
/// L'ordre et le séparateur sont figés : ne JAMAIS les changer sans re-générer
/// toutes les bases (sinon les anciennes clés ne matcheront plus).
pub fn canonical_composite(
    prenom: &str, nom: &str, date_naissance: &str, nss: &str,
) -> Result<String, CryptoError> {
    let nss_n    = normalize_nss(nss)?;
    let date_n   = normalize_date(date_naissance)?;
    let nom_n    = normalize_name(nom);
    let prenom_n = normalize_name(prenom);
    if nom_n.is_empty() {
        return Err(CryptoError::InvalidInput("nom vide après normalisation".into()));
    }
    if prenom_n.is_empty() {
        return Err(CryptoError::InvalidInput("prénom vide après normalisation".into()));
    }
    Ok(format!("{nss_n}|{date_n}|{nom_n}|{prenom_n}"))
}

/// Dérive la clé de correspondance fixe (32 o) d'un patient.
/// `MatchKey = SHA-256(composite canonique)`.
/// Le composite (sensible) est zeroisé de la mémoire après hachage.
pub fn derive_match_key(
    prenom: &str, nom: &str, date_naissance: &str, nss: &str,
) -> Result<MatchKey, CryptoError> {
    let mut composite = canonical_composite(prenom, nom, date_naissance, nss)?;

    let mut hasher = Sha256::new();
    hasher.update(composite.as_bytes());
    let digest = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);

    composite.zeroize(); // efface le composite en clair de la mémoire (CESTI)
    Ok(key)
}

/// Représentation hexadécimale d'une clé (pour journaux / messages d'erreur).
pub fn key_hex(key: &MatchKey) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

// ============================================================================
//  Tests — exécuter avec `cargo test -p dpeg_shared`
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accents_et_casse_matchent() {
        // « François » (Paris) doit matcher « FRANCOIS » (Rennes).
        let a = derive_match_key("François", "Petit", "30/11/1982", "177016634567890").unwrap();
        let b = derive_match_key("francois", "PETIT", "1982-11-30", "177016634567890").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn tirets_et_espaces_matchent() {
        // « Jean-Pierre » == « jean pierre » == « JeanPierre »
        let a = derive_match_key("Jean-Pierre", "Dupont", "15/07/1975", "285094523456789").unwrap();
        let b = derive_match_key("jean pierre", "dupont", "15-07-1975", "285094523456789").unwrap();
        let c = derive_match_key("JeanPierre", "Dupont", "1975/07/15", "285094523456789").unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn apostrophe_et_nss_avec_espaces() {
        let a = derive_match_key("Sophie", "O'Brien", "03/04/1991", "275126789012345").unwrap();
        let b = derive_match_key("sophie", "OBrien",  "1991-04-03", "2 75 12 67 89 012 345").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn patients_differents_ne_matchent_pas() {
        let a = derive_match_key("Alice", "Martin", "05/05/1985", "180057501234567").unwrap();
        let b = derive_match_key("Hugo",  "Moreau", "22/09/1979", "411098156789012").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn nss_invalide_rejete() {
        assert!(derive_match_key("Alice", "Martin", "05/05/1985", "123").is_err());
    }

    #[test]
    fn date_invalide_rejetee() {
        assert!(derive_match_key("Alice", "Martin", "32/13/1985", "180057501234567").is_err());
    }

    #[test]
    fn limite_connue_umlaut_vs_ue() {
        // LIMITE DOCUMENTÉE : « Müller » → « muller », « Mueller » → « mueller ».
        // Ces deux graphies NE matchent PAS (translittération allemande).
        let a = derive_match_key("Hans", "Müller",  "01/01/1970", "180017012345678").unwrap();
        let b = derive_match_key("Hans", "Mueller", "01/01/1970", "180017012345678").unwrap();
        assert_ne!(a, b);
    }
}
