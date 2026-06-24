// ─────────────────────────────────────────────────────────────
// node/src/export.rs — Export du résultat final en CSV (initiateur)
//
// L'intersection est une liste de MatchKey (hash composite). Pour produire un
// résultat lisible, on réassocie chaque clé à l'identité du patient via le
// registre du prologue (clé → PatientRecord). Réservé à l'initiateur.
// ─────────────────────────────────────────────────────────────

use std::collections::HashMap;
use dpeg_shared::crypto_error::crypto_error::CryptoError;
use dpeg_shared::exactmatch::types::MatchKey;
use dpeg_shared::exactmatch::canonical::key_hex;

use crate::prologue::PatientRecord;

/// Écrit le résultat de l'intersection PSI dans un fichier CSV.
///
/// `matched`  : clés des patients communs (sortie de decrypt_round2).
/// `registry` : registre clé → identité de l'initiateur (sortie du prologue).
pub fn write_intersection_csv(
    matched:  &[MatchKey],
    registry: &HashMap<MatchKey, PatientRecord>,
    output_path: &str,
) -> Result<(), CryptoError> {
    use std::fs::File;
    use std::io::{BufWriter, Write};

    let err = |e: std::io::Error| CryptoError::CsvIo {
        path: output_path.to_string(), source: e.to_string(),
    };

    let file = File::create(output_path).map_err(err)?;
    let mut w = BufWriter::new(file);

    writeln!(w, "nombre total de patients communs: {}", matched.len()).map_err(err)?;
    writeln!(w, "Position Locale,Matricule INS,Prenom,Nom,Date de naissance").map_err(err)?;

    for (i, key) in matched.iter().enumerate() {
        match registry.get(key) {
            Some(p) => writeln!(w, "{},{},{},{},{}",
                i + 1, p.nss, p.prenom, p.nom, p.date_naissance).map_err(err)?,
            // Ne devrait pas arriver : l'initiateur matche ses propres clés.
            None => writeln!(w, "{},<clé inconnue {}>,,,", i + 1, key_hex(key)).map_err(err)?,
        }
    }
    w.flush().map_err(err)?;

    println!("── [Output] {} patients communs écrits dans '{}'", matched.len(), output_path);
    Ok(())
}
