use std::fmt;

#[derive(Debug)]
pub enum CryptoError {

    
    EncryptionError(String),
    DecryptionError(String),
    InvalidParameters(String),
    ArithmeticOverflow,
    RandomnessError(String),

    // Chargement CSV 
    CsvIo {
        path:   String,
        source: String,
    },

    CsvEmpty(String),

    CsvColumnNotFound {
        file:   String,
        column: String,
    },

    /// Robustesse lecture ligne
    CsvReadLineError {
        file: String,
        source: String,
    },

    /// Ligne CSV mal formée (erreur de parsing, nombre de colonnes incorrect,
    /// cellule manquante, valeur vide là où on en attendait une).
    /// `line_number` est 1-based et inclut l'en-tête (donc la première ligne
    /// de données est la ligne 2).
    CsvMalformedLine {
        path:        String,
        line_number: u64,
        reason:      String,
    },

    /// NSS invalide : ne respecte pas le format attendu
    /// (uniquement des chiffres ASCII, longueur 13 ou 15).
    CsvInvalidNss {
        path:        String,
        line_number: u64,
        value:       String,
    },

    // Encodage identifiant 
    EncodeOutOfRange {
        id: String,
    },

    // Paramètres invalides 
    InvalidParam(String),

    
    InvalidBeta,

    
    InvalidModulus,

    // Inverse modulaire 
    ModInverseUndefined,

    //  Génération de clé 
    KeyGenFailed(String),

    // Calcul de N
    NOverflow,

    EmptyDatabase {
        which: &'static str,
    },

    //  Chiffrement 
    EncryptFailed(String),

    //  Déchiffrement 
    DecryptFailed(String),

    // Pseudonymisation
    FHEnymFailed(String),

    // Tailles EDB incompatibles 
    EdbSizeMismatch {
        len1: usize,
        len2: usize,
    },

     MessageOutOfRange,
    /// Le chiffré c est > n^2 (hors domaine ciphertext Paillier)
    CiphertextOutOfRange,
    /// La taille de clé demandée est trop petite (< MIN_KEY_BITS)
    KeySizeTooSmall { requested: u64, minimum: u64 },

    // Erreurs mathématiques internes 
    /// L'inverse modulaire n'existe pas (gcd != 1)
    NoModularInverse,
    /// Conversion BigInt -> BigUint échouée (résultat négatif — invariant interne)
    NegativeConversion,
    /// Argument u = 0 passé à l_function : u - 1 est indéfini sur BigUint
    /// (l_function exige u ≥ 1, i.e. u ∈ Z/n^2Z non nul)
    LFunctionInputZero,

    // Erreurs de stockage / parsing des clés 
    /// Parsing hexadécimal invalide dans un champ de clé JSON
    HexParseError,
    /// Champ hex trop long : vecteur DoS potentiel (conversion BigUint coûteuse)
    HexFieldTooLong { actual: usize, maximum: usize },
    /// n_squared != n*n au chargement : fichier corrompu ou falsifié
    KeyCoherenceError,

    // Erreurs KEA
    /// La vérification d'image KEA a échoué (chiffré invalide ou falsifié)
    KeaImVerFailed,
    /// Erreur générique pour les entrées invalides
    InvalidInput(String),

    /// Erreur provenant du registre de clés
    RegistryError(String),

    // ─────────────────────────────────────────────────────────────
    // Erreurs de communication (réseau H1 ↔ H2 ↔ Serveur)
    // ─────────────────────────────────────────────────────────────
    /// Connexion réseau impossible avec un pair
    NetworkConnectFailed { peer: String, reason: String },
    /// Envoi de données échoué
    NetworkSendFailed   { peer: String, what: String, reason: String },
    /// Réception de données échouée
    NetworkReceiveFailed{ peer: String, what: String, reason: String },
    /// Timeout dépassé pendant un échange
    NetworkTimeout      { peer: String, what: String },
    /// Message reçu mal formé ou incomplet
    NetworkMalformedMessage { peer: String, reason: String },
    /// Taille de payload dépasse la limite autorisée (protection DoS)
    NetworkPayloadTooLarge  { actual: usize, maximum: usize },

    // ─────────────────────────────────────────────────────────────
    // Erreurs de validation des données reçues
    // ─────────────────────────────────────────────────────────────
    /// Clé publique reçue invalide
    InvalidPublicKey   { reason: String },
    /// Taille de table EDB inattendue
    InvalidEdbSize     { expected: usize, actual: usize },
    /// Authentification d'un pair échouée (mTLS, signature)
    PeerAuthenticationFailed { peer: String },

}

// ─────────────────────────────────────────────────────────────
// Display
// ─────────────────────────────────────────────────────────────
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionError(s) =>
                write!(f, "[Paillier] Erreur de chiffrement : {}", s),

            CryptoError::DecryptionError(s) =>
                write!(f, "[Paillier] Erreur de déchiffrement : {}", s),

            CryptoError::FHEnymFailed(s) =>
                write!(f, "[Paillier] Erreur de Pseudonymisation : {}", s),

            CryptoError::InvalidParameters(s) =>
                write!(f, "[Paillier] Paramètres invalides : {}", s),

            CryptoError::ArithmeticOverflow =>
                write!(f, "[Arithmétique] Débordement BigUint"),

            CryptoError::RandomnessError(s) =>
                write!(f, "[RNG] Erreur d'entropie : {}", s),

            CryptoError::CsvIo { path, source } =>
                write!(f, "[CSV] Impossible d'ouvrir '{}' : {}", path, source),

            CryptoError::CsvEmpty(path) =>
                write!(f, "[CSV] Fichier vide ou sans en-tête : '{}'", path),

            CryptoError::CsvColumnNotFound { file, column } =>
                write!(f, "[CSV] Colonne '{}' absente dans '{}'", column, file),

            CryptoError::CsvReadLineError { file, source } =>
                write!(f, "[CSV] Erreur lecture ligne dans '{}' : {}", file, source),

            CryptoError::CsvMalformedLine { path, line_number, reason } =>
                write!(f,
                    "[CSV] Ligne {} mal formée dans '{}' : {}",
                    line_number, path, reason
                ),

            CryptoError::CsvInvalidNss { path, line_number, value } =>
                write!(f,
                    "[CSV] NSS invalide ligne {} dans '{}' : '{}' \
                     (attendu : 13 ou 15 chiffres)",
                    line_number, path, value
                ),

            CryptoError::EncodeOutOfRange { id } =>
                write!(f, "[Encode] SHA-256({}) >= pk.n", id),

            CryptoError::InvalidParam(s) =>
                write!(f, "[Param] Paramètre invalide : {}", s),

            CryptoError::InvalidBeta =>
                write!(f, "[Param] beta doit être >= 1"),

            CryptoError::InvalidModulus =>
                write!(f, "[Param] Modulus invalide (n <= 1)"),

            CryptoError::ModInverseUndefined =>
                write!(f, "[HE] Inverse modulaire inexistant (gcd != 1)"),

            CryptoError::KeyGenFailed(s) =>
                write!(f, "[Setup] KeyGen échoué : {}", s),

            CryptoError::NOverflow =>
                write!(f, "[Setup] Overflow dans le calcul de N"),

            CryptoError::EmptyDatabase { which } =>
                write!(f, "[Setup] Base vide : {}", which),

            CryptoError::EncryptFailed(s) =>
                write!(f, "[HE] p_encrypt() échoué : {}", s),

            CryptoError::DecryptFailed(s) =>
                write!(f, "[HE] p_decrypt() échoué : {}", s),

            CryptoError::EdbSizeMismatch { len1, len2 } =>
                write!(f,
                    "[Round1] Taille mismatch EDB1={} EDB2={}",
                    len1, len2
                ),
            CryptoError::MessageOutOfRange =>
                write!(f, "Le message doit être dans [0, n)"),
            CryptoError::CiphertextOutOfRange =>
                write!(f, "Le chiffré doit être dans [0, n²)"),
            CryptoError::KeySizeTooSmall { requested, minimum } =>
                write!(f, "Taille de clé {requested} bits insuffisante, \
                           minimum requis : {minimum} bits"),
            CryptoError::NoModularInverse =>
                write!(f, "Impossible de calculer l'inverse modulaire (gcd != 1)"),
            CryptoError::NegativeConversion =>
                write!(f, "Conversion interne BigInt -> BigUint : \
                           résultat négatif inattendu"),
            CryptoError::LFunctionInputZero =>
                write!(f, "l_function : argument u = 0 invalide \
                           (u doit être ≥ 1 dans Z/n^2Z)"),
            CryptoError::HexParseError =>
                write!(f, "Parsing hexadécimal invalide dans le fichier de clés"),
            CryptoError::HexFieldTooLong { actual, maximum } =>
                write!(f, "Champ hexadécimal trop long : {actual} caractères \
                           (maximum autorisé : {maximum})"),
            CryptoError::KeyCoherenceError =>
                write!(f, "Fichier de clés incohérent : n_squared != n*n \
                           (corrompu ou falsifié)"),
            CryptoError::KeaImVerFailed =>
                write!(f, "Vérification d'image KEA échouée : \
                           chiffré invalide ou falsifié"),
            CryptoError::InvalidInput(msg) =>
                write!(f, "Entrée invalide : {msg}"),
            CryptoError::RegistryError(msg) =>
                write!(f, "[Registry] {msg}"),

            // ── Erreurs de communication ──────────────────────────
            CryptoError::NetworkConnectFailed { peer, reason } =>
                write!(f, "[Network] Connexion à {peer} impossible : {reason}"),
            CryptoError::NetworkSendFailed { peer, what, reason } =>
                write!(f, "[Network] Envoi de {what} vers {peer} échoué : {reason}"),
            CryptoError::NetworkReceiveFailed { peer, what, reason } =>
                write!(f, "[Network] Réception de {what} depuis {peer} échouée : {reason}"),
            CryptoError::NetworkTimeout { peer, what } =>
                write!(f, "[Network] Timeout pendant {what} avec {peer}"),
            CryptoError::NetworkMalformedMessage { peer, reason } =>
                write!(f, "[Network] Message mal formé reçu de {peer} : {reason}"),
            CryptoError::NetworkPayloadTooLarge { actual, maximum } =>
                write!(f, "[Network] Payload trop volumineux : {actual} octets \
                           (maximum {maximum}) — protection DoS"),

            // ── Erreurs de validation des données reçues ──────────
            CryptoError::InvalidPublicKey { reason } =>
                write!(f, "[Validation] Clé publique invalide : {reason}"),
            CryptoError::InvalidEdbSize { expected, actual } =>
                write!(f, "[Validation] Taille EDB invalide : attendu {expected}, \
                           reçu {actual}"),
            CryptoError::PeerAuthenticationFailed { peer } =>
                write!(f, "[Validation] Authentification de {peer} échouée"),
        }
        }
    }


impl std::error::Error for CryptoError {}