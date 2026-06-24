# Projet-DPEG v1.0.0 — PSI-ExactMatch (bibliothèques, sans transport)

PSI ExactMatch (Depth-0) entre hôpitaux sous chiffrement homomorphe de Paillier
2048 bits. Cette version expose **uniquement le code** : la logique
cryptographique est répartie en bibliothèques séparées, **sans aucune couche
réseau** (ni TCP, ni mTLS).

Le module FHEnymisation a été retiré (et sera développer dans un autre module).
Le code du demo n'intervient pas en production, donc peut être ignorer lors de l'intégration dans le système

## Séparation des crates

```
Projet-DPEG/
├── shared/   bibliothèque commune (primitives, types, sérialisation)
│   ├── paillier/        keygen, encrypt, decrypt, math
│   ├── exactmatch/      types, hash, csv, edb, setup, binned_psi
│   ├── codec.rs         (dé)sérialisation transport-agnostique — AUCUNE I/O
│   └── crypto_error, key_management, session, config
│
├── node/     bibliothèque UNIQUE de l'hôpital (H1…H10) — ex-h1 + ex-h2 fusionnés
│   ├── lib.rs           API par rôle (initiateur / participant)
│   ├── round1.rs        decrypt_round1            (initiateur)
│   ├── round2.rs        h1_buckets, h1_labels, h2_buckets, decrypt_round2
│   └── export.rs        write_intersection_csv    (initiateur)
│
├── server/   bibliothèque de calcul homomorphe Depth-0 (ne détient que pk)
│   └── exactmatch/      he_add/sub/smul, eval_round1, eval_round2
│
└── demo/     harnais EN MÉMOIRE (sans réseau) qui orchestre node + server
    └── src/main.rs      montre la séquence + les frontières [TRANSPORT]
```

> `node` et `server` ne dépendent **pas** l'un de l'autre. Seul `demo` dépend
> des deux : c'est un harnais de test, pas un composant de production.
>
> `fiore_catalano/` et `paillier_kea/` sont conservés dans le serveur mais ne
> sont pas utilisés par le PSI.

## Pas de transport : ce que le backend doit faire

Aucune fonction de ce dépôt n'ouvre de socket. Le backend appelle les
bibliothèques et achemine lui-même les données entre les services. Les frontières
sont matérialisées dans `demo/src/main.rs` par des marqueurs `[TRANSPORT]`.

Données qui traversent chaque frontière (toutes sérialisables via `dpeg_shared::codec`) :

| De → Vers                 | Donnée                    | Helpers codec                          |
|---------------------------|---------------------------|----------------------------------------|
| init → serveur            | `pk`                      | `encode_pk` / `decode_pk`              |
| init/part → serveur       | taille de base (→ N)      | `encode_usize` / `decode_usize`        |
| serveur → participant     | `pk` (relayée)            | `encode_pk` / `decode_pk`              |
| init/part → serveur       | `EDB`                     | `encode_vec_biguint` / `decode_…`      |
| serveur → init            | `Eres`                    | `encode_vec_biguint` / `decode_…`      |
| **init → participant**    | `MatchedPos` *(direct)*   | `encode_pos` / `decode_pos`            |
| **participant → init**    | comptes par position *(direct)* | `encode_counts` / `decode_counts` |
| init/part → serveur       | buckets Round 2           | `encode_buckets` / `decode_buckets`    |
| serveur → init            | `Echeck`                  | `encode_vec_biguint` / `decode_…`      |

> `MatchedPos` et les comptes circulent **en direct** initiateur ↔ participant.
> Ils ne doivent JAMAIS passer par le serveur (il apprendrait la structure de
> l'intersection). Le backend doit prévoir un canal init ↔ participant.

Le backend peut utiliser `codec` tel quel, ou son propre format (serde,
protobuf…) : dans ce cas, le tableau ci-dessus documente les types à transmettre.

## API du nœud (rôle = jeu de fonctions appelées)

Le même crate `dpeg_node` sert les deux rôles ; c'est le backend qui choisit
quelles fonctions appeler.

* **Initiateur** (déclenche, détient `sk`, obtient le résultat) :
  `keygen` → `build_database` → `decrypt_round1` → `h1_buckets` + `h1_labels`
  → `decrypt_round2` → `write_intersection_csv`
* **Participant** (chiffre seulement, jamais `sk`, aucun résultat) :
  `build_database` → `h2_buckets` → `counts_of`

Si demain c'est H7 qui déclenche, son backend appelle simplement les fonctions
« initiateur ». Aucune ligne de code ne change. Le protocole est **par paire**.

## Vérifier de bout en bout (sans réseau)

```bash
cargo run -p dpeg_demo
# ou avec vos fichiers : cargo run -p dpeg_demo -- mon_init.csv mon_part.csv 1.0
```

Données de test fournies (`hopital_A.csv`, `hopital_B.csv`) : 3 patients communs
(Bob, David, Emma). Sortie attendue → `intersection_demo.csv`.

Format CSV : en-tête `NSS;prenom;nom` (séparateur `;`, `,`, tab ou `|` détecté) ;
NSS de 13 ou 15 chiffres.

## Migration depuis v0.5

* Suppression de toute la couche réseau : `node/protocol.rs`, les `main.rs`
  réseau de `node` et `server`, `shared/wire.rs` et `shared/net_protocol/`.
* `node` et `server` deviennent des **bibliothèques** (`lib`), sans binaire.
* Nouveau `shared/codec.rs` : sérialisation pure (aucune I/O) pour le backend.
* Nouveau crate `demo` : exécution en mémoire montrant la séquence complète et
  les points `[TRANSPORT]` à brancher.
* Champs `csv_pseudo_*` dans `config.rs`/`session.rs` : inertes, non utilisés.

## v0.7 — Clé composite + prologue

Le PSI ne matche plus sur le seul NSS mais sur le **hash de (prénom, nom, date
de naissance, NSS)**. La clé de correspondance est `MatchKey = [u8;32]`
(SHA-256 du composite canonique) — taille fixe, boucles à borne connue,
zeroization triviale.

**`node/src/prologue.rs`** (préparation CSV, exécutée par chaque hôpital) :
- localise les colonnes via un **dictionnaire d'alias extensible**
  (`ColumnDictionary`, à enrichir au fil des clients) ;
- normalise chaque champ de façon **identique pour tous les hôpitaux**
  (`dpeg_shared::exactmatch::canonical`) : accents retirés, minuscule, tirets et
  espaces ignorés, date → `YYYYMMDD`, NSS → chiffres (13/15) ;
- dérive la `MatchKey`, **déduplique** les patients, et construit un registre
  `clé → identité` (export, initiateur uniquement).

**Règle critique** : tous les hôpitaux doivent utiliser la MÊME normalisation et
la MÊME fonction de hachage, sinon aucun match. C'est garanti par le crate
partagé `dpeg_shared::canonical`.

**Limites documentées** (cf. tests) : « Müller » ≠ « Mueller », « ß » non
translittéré. À signaler aux clients dont les bases contiennent des noms
d'origine germanique.

## v0.8 — Chiffrement KEA (Paillier P², intégrité CCA1)

Tous les chiffrements/déchiffrements du PSI utilisent désormais **paillier_kea**
(schéma P², KEA) au lieu de Paillier simple, pour l'intégrité **CCA1**.

**Principe** : un chiffré KEA est une PAIRE `(Enc(m), Enc(ψ·m))`. La relation
`ψ·m` est linéaire, donc préservée par `he_add` / `he_sub` / `he_smul`
(appliqués composante par composante). Au déchiffrement, `img_verif` vérifie
`ψ·Dec(c0) == Dec(c1)` : tout chiffré falsifié ou malformé est rejeté
(`CryptoError::KeaImVerFailed`). C'est le gain d'intégrité face à un serveur ou
un participant malveillant qui soumettrait des chiffrés invalides.

**Clés** : l'initiateur génère, après `keygen`, une clé KEA :
```rust
let (pk, sk) = keygen(bits)?;
let kea = paillier_kea_keygen(&pk)?;   // kea.ct_delta (public), kea.psy (secret)
```
`ct_delta` est distribué AVEC `pk` (les deux hôpitaux chiffrent avec). `psy`
reste chez l'initiateur, avec `sk`, et sert au déchiffrement+vérification.

**Signatures impactées** :
- `h1_buckets` / `h2_buckets(map, pos, pk, ct_delta)`  ← `ct_delta` ajouté
- `decrypt_round1(edb, pk, sk, psy)` / `decrypt_round2(echeck, labels, pk, sk, psy)` ← `psy` ajouté
- `Edb`, buckets, `Eres`, `Echeck` transportent des `KeaCt = (BigUint, BigUint)`

**Migration** : `paillier_kea` a été déplacé de `server/` vers `shared/`
(le client chiffre aussi). Les cases EDB chiffrent 0 → `(Enc(0), Enc(0))`,
sans `ct_delta` (rapide) ; seuls les buckets paient l'exponentiation `ct_delta`.

**Coût** : ~2× (chiffré double ; déchiffrement = 2 déchiffrements pour vérifier).
Optimisation possible : `paillier_kea_decrypt` re-déchiffre `c0` après img_verif
(3 déchiffrements au total) — réutiliser `mu_0` le ramènerait à 2.
