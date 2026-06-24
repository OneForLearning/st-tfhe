// ─────────────────────────────────────────────────────────────
// csv_reader.rs — Chargement des fichiers CSV patients
//
// Détection automatique du séparateur : ; , \t |
// Validation stricte des NSS (longueur 13 ou 15, chiffres ASCII)
// ─────────────────────────────────────────────────────────────

use std::collections::HashMap;
use crate::crypto_error::crypto_error::CryptoError;

/// Détecte le séparateur d'un fichier CSV à partir de son en-tête.
/// Priorité : ';' > '\t' > '|' > ',' (défaut)
fn detect_separator(header: &str) -> u8 {
    if header.contains(';')       { b';'  }
    else if header.contains('\t') { b'\t' }
    else if header.contains('|')  { b'|'  }
    else                          { b','  }
}

/// Charge la liste des NSS depuis un fichier CSV.
///
/// Détecte automatiquement le séparateur (; , \t |).
/// Cherche la colonne "NSS" (ou "id" en mode virgule).
/// Valide chaque NSS : longueur 13 ou 15, chiffres ASCII uniquement.
pub fn load_nss_from_csv(path: &str) -> Result<Vec<String>, CryptoError> {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    use csv::ReaderBuilder;

    // 1. Détection du séparateur sur la première ligne
    let file = File::open(path)
        .map_err(|e| CryptoError::CsvIo {
            path:   path.to_string(),
            source: e.to_string(),
        })?;

    let mut reader = BufReader::new(file);
    let mut header_line = String::new();
    let bytes_read = reader.read_line(&mut header_line)
        .map_err(|e| CryptoError::CsvIo {
            path:   path.to_string(),
            source: e.to_string(),
        })?;

    if bytes_read == 0 {
        return Err(CryptoError::CsvEmpty(path.to_string()));
    }

    let header = header_line.trim();
    let sep    = detect_separator(header);

    // Rembobinage pour que le parseur CSV re-lise l'en-tête
    let mut file = reader.into_inner();
    file.seek(SeekFrom::Start(0))
        .map_err(|e| CryptoError::CsvIo {
            path:   path.to_string(),
            source: e.to_string(),
        })?;

    // 2. Construction du parseur CSV
    let mut csv_reader = ReaderBuilder::new()
        .delimiter(sep)
        .has_headers(true)
        .flexible(false)
        .from_reader(file);

    // 3. Recherche de la colonne NSS
    let headers = csv_reader.headers()
        .map_err(|e| CryptoError::CsvIo {
            path:   path.to_string(),
            source: e.to_string(),
        })?;

    let col_idx = if sep == b';' {
        headers.iter().position(|c| c.trim() == "NSS")
            .ok_or_else(|| CryptoError::CsvColumnNotFound {
                file:   path.to_string(),
                column: "NSS".to_string(),
            })?
    } else {
        headers.iter().position(|c| c.trim() == "NSS")
            .or_else(|| headers.iter().position(|c| c.trim() == "id"))
            .ok_or_else(|| CryptoError::CsvColumnNotFound {
                file:   path.to_string(),
                column: "NSS or id".to_string(),
            })?
    };

    // 4. Extraction et validation des NSS
    let mut result: Vec<String> = Vec::new();

    for (i, record) in csv_reader.records().enumerate() {
        let line_number = (i as u64) + 2;

        let record = record.map_err(|e| CryptoError::CsvMalformedLine {
            path:        path.to_string(),
            line_number,
            reason:      e.to_string(),
        })?;

        let val = record.get(col_idx)
            .ok_or_else(|| CryptoError::CsvMalformedLine {
                path:        path.to_string(),
                line_number,
                reason:      format!("colonne d'index {} absente", col_idx),
            })?
            .trim()
            .to_string();

        if val.is_empty() {
            return Err(CryptoError::CsvMalformedLine {
                path:        path.to_string(),
                line_number,
                reason:      "NSS vide".to_string(),
            });
        }

        // Validation : uniquement chiffres ASCII, longueur 13 ou 15
        let is_valid_nss = (val.len() == 13 || val.len() == 15)
            && val.bytes().all(|b| b.is_ascii_digit());

        if !is_valid_nss {
            return Err(CryptoError::CsvInvalidNss {
                path:        path.to_string(),
                line_number,
                value:       val,
            });
        }

        result.push(val);
    }

    Ok(result)
}

/// Charge la map NSS -> (prénom, nom) depuis un fichier CSV.
///
/// Détecte automatiquement le séparateur (; , \t |).
/// Cherche les colonnes "nss", "prenom", "nom" (insensible à la casse).
pub fn load_patient_map(
    path: &str,
) -> Result<HashMap<String, (String, String)>, CryptoError> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(path)
        .map_err(|e| CryptoError::CsvIo {
            path:   path.to_string(),
            source: e.to_string(),
        })?;

    let reader     = BufReader::new(file);
    let mut lines  = reader.lines();

    let header_line = lines
        .next()
        .ok_or_else(|| CryptoError::CsvEmpty(path.to_string()))?
        .map_err(|e| CryptoError::CsvIo { path: path.to_string(), source: e.to_string() })?;
    let header = header_line.trim();

    let sep  = detect_separator(header) as char;
    let cols: Vec<&str> = header.split(sep).collect();
    let eq = |c: &&str, name: &str| c.trim().to_lowercase() == name;

    let nss_idx = cols.iter().position(|c| eq(c, "nss"))
        .ok_or_else(|| CryptoError::CsvColumnNotFound {
            file:   path.to_string(),
            column: "nss".to_string(),
        })?;
    let prenom_idx = cols.iter().position(|c| eq(c, "prenom"))
        .ok_or_else(|| CryptoError::CsvColumnNotFound {
            file:   path.to_string(),
            column: "prenom".to_string(),
        })?;
    let nom_idx = cols.iter().position(|c| eq(c, "nom"))
        .ok_or_else(|| CryptoError::CsvColumnNotFound {
            file:   path.to_string(),
            column: "nom".to_string(),
        })?;

    let mut map = HashMap::new();
    for line in lines {
        let l   = match line { Ok(l) => l, Err(_) => continue };
        let row: Vec<&str> = l.split(sep).collect();
        let nss    = row.get(nss_idx).map(|s| s.trim().to_string()).unwrap_or_default();
        let prenom = row.get(prenom_idx).map(|s| s.trim().to_string()).unwrap_or_default();
        let nom    = row.get(nom_idx).map(|s| s.trim().to_string()).unwrap_or_default();
        if !nss.is_empty() {
            map.insert(nss, (prenom, nom));
        }
    }

    Ok(map)
}