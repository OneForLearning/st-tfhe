// ============================================================================
//  node/src/prologue.rs — Préparation des fichiers CSV (côté hôpital)
//
//  À exécuter par CHAQUE hôpital participant, AVANT le PSI. Étapes :
//    1. Lecture du CSV uploadé (séparateur ; , \t | détecté automatiquement)
//    2. Localisation des colonnes sensibles via un DICTIONNAIRE d'alias
//       extensible (prénom, nom, date de naissance, NSS)
//    3. Normalisation canonique IDENTIQUE pour tous (dpeg_shared::canonical)
//    4. Dérivation de la clé de correspondance fixe MatchKey = [u8;32]
//    5. DÉDUPLICATION des patients (clés identiques → une seule occurrence)
//    6. Registre clé → identité (réservé à l'initiateur, pour l'export final)
//
//  La sortie `PreparedDataset.keys` alimente directement `build_database`.
//  AUCUN transport ici : le backend décide comment acheminer les données.
// ============================================================================

use std::collections::{HashMap, HashSet};

use dpeg_shared::crypto_error::crypto_error::CryptoError;
use dpeg_shared::exactmatch::canonical::derive_match_key;
use dpeg_shared::exactmatch::types::MatchKey;

/// Identité d'un patient telle que lue dans le CSV (champs bruts).
/// Conservée UNIQUEMENT côté initiateur, dans le registre, pour l'export final.
#[derive(Clone, Debug)]
pub struct PatientRecord {
    pub prenom: String,
    pub nom: String,
    pub date_naissance: String,
    pub nss: String,
}

/// Dictionnaire d'alias de colonnes — À ENRICHIR au fil des clients.
/// Chaque champ canonique liste les en-têtes acceptés (comparés en minuscules,
/// après suppression des accents). Permet d'absorber les variantes de nommage
/// des CSV hospitaliers sans changer le code appelant.
#[derive(Clone, Debug)]
pub struct ColumnDictionary {
    pub nss: Vec<String>,
    pub nom: Vec<String>,
    pub prenom: Vec<String>,
    pub date_naissance: Vec<String>,
}

impl Default for ColumnDictionary {
    fn default() -> Self {
        let v = |items: &[&str]| items.iter().map(|s| s.to_string()).collect();
        ColumnDictionary {
            nss:            v(&["nss", "ins", "matricule", "matricule ins",
                                "numero secu", "numero securite sociale", "nir", "id"]),
            nom:            v(&["nom", "nom de naissance", "nom famille",
                                "lastname", "last name", "surname", "family name"]),
            prenom:         v(&["prenom", "prenoms", "firstname", "first name",
                                "given name"]),
            date_naissance: v(&["date naissance", "date de naissance", "naissance",
                                "ddn", "dob", "birthdate", "birth date",
                                "date of birth"]),
        }
    }
}

/// Résultat de la préparation d'un CSV.
pub struct PreparedDataset {
    /// Clés de correspondance, dédupliquées. Alimente `build_database`.
    pub keys: Vec<MatchKey>,
    /// Registre clé → identité (pour l'export final, initiateur uniquement).
    pub registry: HashMap<MatchKey, PatientRecord>,
    /// Nombre de doublons exacts éliminés.
    pub duplicates_removed: usize,
    /// Lignes ignorées car invalides : (numéro de ligne, raison).
    pub invalid_rows: Vec<(usize, String)>,
}

// ── Normalisation d'en-tête pour la recherche d'alias (accents + minuscule) ──
fn norm_header(h: &str) -> String {
    use dpeg_shared::exactmatch::canonical::normalize_name;
    // normalize_name retire accents + minuscule + garde alphanumérique.
    // On insère un espace à la place des séparateurs pour comparer mot à mot :
    // ici on compresse tout, donc "Date de naissance" → "datedenaissance".
    // Les alias du dictionnaire sont donc comparés sous leur forme compressée.
    normalize_name(h)
}

fn find_column(headers: &[String], aliases: &[String]) -> Option<usize> {
    let norm_aliases: Vec<String> = aliases.iter().map(|a| norm_header(a)).collect();
    headers.iter().position(|h| {
        let nh = norm_header(h);
        norm_aliases.iter().any(|a| *a == nh)
    })
}

fn detect_separator(header: &str) -> u8 {
    if header.contains(';')       { b';'  }
    else if header.contains('\t') { b'\t' }
    else if header.contains('|')  { b'|'  }
    else                          { b','  }
}

/// Prépare un fichier CSV : extraction, normalisation, clés, déduplication.
pub fn prepare_csv(path: &str, dict: &ColumnDictionary) -> Result<PreparedDataset, CryptoError> {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    use csv::ReaderBuilder;

    // 1. Détection du séparateur sur la première ligne.
    let file = File::open(path).map_err(|e| CryptoError::CsvIo {
        path: path.to_string(), source: e.to_string(),
    })?;
    let mut buf = BufReader::new(file);
    let mut first = String::new();
    if buf.read_line(&mut first).map_err(|e| CryptoError::CsvIo {
        path: path.to_string(), source: e.to_string(),
    })? == 0 {
        return Err(CryptoError::CsvEmpty(path.to_string()));
    }
    let sep = detect_separator(first.trim());

    let mut file = buf.into_inner();
    file.seek(SeekFrom::Start(0)).map_err(|e| CryptoError::CsvIo {
        path: path.to_string(), source: e.to_string(),
    })?;

    // 2. Parseur + localisation des colonnes via le dictionnaire.
    let mut rdr = ReaderBuilder::new()
        .delimiter(sep).has_headers(true).flexible(true).from_reader(file);

    let headers: Vec<String> = rdr.headers()
        .map_err(|e| CryptoError::CsvIo { path: path.to_string(), source: e.to_string() })?
        .iter().map(|s| s.to_string()).collect();

    let col = |field: &str, aliases: &[String]| -> Result<usize, CryptoError> {
        find_column(&headers, aliases).ok_or_else(|| CryptoError::CsvColumnNotFound {
            file: path.to_string(), column: field.to_string(),
        })
    };
    let i_nss    = col("NSS",            &dict.nss)?;
    let i_nom    = col("nom",            &dict.nom)?;
    let i_prenom = col("prenom",         &dict.prenom)?;
    let i_date   = col("date_naissance", &dict.date_naissance)?;

    // 3-6. Extraction, dérivation, déduplication, registre.
    let mut keys = Vec::new();
    let mut registry = HashMap::new();
    let mut seen: HashSet<MatchKey> = HashSet::new();
    let mut duplicates_removed = 0usize;
    let mut invalid_rows = Vec::new();

    for (i, rec) in rdr.records().enumerate() {
        let line = i + 2; // +1 en-tête, +1 base 1
        let rec = match rec {
            Ok(r) => r,
            Err(e) => { invalid_rows.push((line, format!("ligne CSV illisible : {e}"))); continue; }
        };
        let get = |idx: usize| rec.get(idx).unwrap_or("").trim().to_string();
        let prenom = get(i_prenom);
        let nom    = get(i_nom);
        let date   = get(i_date);
        let nss    = get(i_nss);

        let key = match derive_match_key(&prenom, &nom, &date, &nss) {
            Ok(k) => k,
            Err(e) => { invalid_rows.push((line, e.to_string())); continue; }
        };

        if !seen.insert(key) {
            duplicates_removed += 1; // déjà vu → doublon exact
            continue;
        }
        keys.push(key);
        registry.insert(key, PatientRecord { prenom, nom, date_naissance: date, nss });
    }

    if keys.is_empty() {
        return Err(CryptoError::EmptyDatabase { which: "CSV (aucune ligne valide)" });
    }
    Ok(PreparedDataset { keys, registry, duplicates_removed, invalid_rows })
}
