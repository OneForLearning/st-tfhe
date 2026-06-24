// ============================================================================
//  demo/src/main.rs — Démo en mémoire du PSI-ExactMatch KEA (sans réseau)
//
//  Enchaîne prologue → node → server avec chiffrement KEA (Paillier P², CCA1).
//  Aux frontières « [TRANSPORT] », les données passent par dpeg_shared::codec.
//
//  Clés : l'initiateur génère (pk, sk) puis la clé KEA (ct_delta public, psy
//  secret). pk + ct_delta sont distribués ; sk + psy restent chez l'initiateur.
//
//  Lancement : cargo run -p dpeg_demo -- [csv_init] [csv_part] [beta]
// ============================================================================

use std::collections::HashMap;

use dpeg_node as node;
use dpeg_node::KeaCt;
use dpeg_server::{eval_round1, eval_round2};
use dpeg_shared::codec;

type R<T> = Result<T, String>;
fn s<E: std::fmt::Display>(e: E) -> String { e.to_string() }

fn main() {
    if let Err(e) = run() {
        eprintln!("\n[ERREUR] {e}");
        std::process::exit(1);
    }
}

fn run() -> R<()> {
    let args: Vec<String> = std::env::args().collect();
    let csv_init = args.get(1).cloned().unwrap_or_else(|| "hopital_A_100.csv".into());
    let csv_part = args.get(2).cloned().unwrap_or_else(|| "hopital_B_100.csv".into());
    let beta: f64 = args.get(3).and_then(|x| x.parse().ok()).unwrap_or(1.0);
    let bits: u64 = 2048;

    println!("\n+==========================================================+");
    println!("|  DEMO PSI-ExactMatch KEA (CCA1) en memoire, sans reseau  |");
    println!("+==========================================================+");
    println!("-- Initiateur : {csv_init}");
    println!("-- Participant: {csv_part}\n");

    // ═══ PROLOGUE ═════════════════════════════════════════════════════════════
    let dict = node::ColumnDictionary::default();
    let prep_init = node::prepare_csv(&csv_init, &dict).map_err(s)?;
    let prep_part = node::prepare_csv(&csv_part, &dict).map_err(s)?;
    report("INIT", &prep_init);
    report("PART", &prep_part);

    // ═══ SETUP (initiateur) : clés Paillier + clé KEA ════════════════════════
    let (pk, sk) = node::keygen(bits).map_err(s)?;
    let kea = node::paillier_kea_keygen(&pk).map_err(s)?; // kea.ct_delta (public), kea.psy (secret)
    println!("[INIT] clés générées ({} bits) — sk + psy restent locales.", pk.n.bits());

    // ── [TRANSPORT] init → serveur : pk ; init → participant : pk + ct_delta.
    let pk_srv = { let b = codec::encode_pk(&pk.n, &pk.g, &pk.n_squared);
                   let (n, g, n2) = codec::decode_pk(&b).map_err(s)?;
                   node::PublicKey { n, g, n_squared: n2 } };
    let pk_part = pk_srv.clone();
    let ctd_part: KeaCt = { let b = codec::encode_ct_delta(&kea.ct_delta);
                            codec::decode_ct_delta(&b).map_err(s)? };

    let big_n = node::compute_n(prep_init.keys.len(), prep_part.keys.len(), beta).map_err(s)?;

    // ═══ EDB (KEA-Enc(0)) ═════════════════════════════════════════════════════
    let (edb_init, map_init) = node::build_database(&prep_init.keys, &pk,      big_n, "INIT").map_err(s)?;
    let (edb_part, map_part) = node::build_database(&prep_part.keys, &pk_part, big_n, "PART").map_err(s)?;

    // ── [TRANSPORT] init/part → serveur : EDB (paires KEA).
    let edb_init_srv = roundtrip_kea_vec(&edb_init)?;
    let edb_part_srv = roundtrip_kea_vec(&edb_part)?;

    // ═══ ROUND 1 (serveur) ════════════════════════════════════════════════════
    let eres = eval_round1(&edb_init_srv, &edb_part_srv, &pk_srv).map_err(s)?;
    let eres_init = roundtrip_kea_vec(&eres)?; // [TRANSPORT] serveur → init

    // Initiateur : déchiffre+vérifie (sk + psy).
    let pos = node::decrypt_round1(&eres_init, &pk, &sk, &kea.psy).map_err(s)?;
    println!("[INIT] Round 1 : {} positions candidates", pos.len());

    // ── [TRANSPORT DIRECT] init → participant : MatchedPos.
    let pos_part = { let b = codec::encode_pos(&pos); codec::decode_pos(&b).map_err(s)? };

    // ═══ ROUND 2 ══════════════════════════════════════════════════════════════
    let b_part = node::h2_buckets(&map_part, &pos_part, &pk_part, &ctd_part).map_err(s)?;
    let counts = node::counts_of(&b_part);
    let counts_init = { let b = codec::encode_counts(&counts); codec::decode_counts(&b).map_err(s)? };

    let b_init = node::h1_buckets(&map_init, &pos, &pk, &kea.ct_delta).map_err(s)?;
    let labels = node::h1_labels(&map_init, &pos, &counts_init);

    // ── [TRANSPORT] init/part → serveur : buckets (paires KEA).
    let b_init_srv = roundtrip_buckets(&b_init)?;
    let b_part_srv = roundtrip_buckets(&b_part)?;

    let echeck = eval_round2(&b_init_srv, &b_part_srv, &pk_srv).map_err(s)?;
    let echeck_init = roundtrip_kea_vec(&echeck)?; // [TRANSPORT] serveur → init

    // ═══ RÉSULTAT (initiateur) ════════════════════════════════════════════════
    let matched = node::decrypt_round2(&echeck_init, &labels, &pk, &sk, &kea.psy).map_err(s)?;
    println!("\n[INIT] Round 2 : {} patients communs :", matched.len());
    for key in &matched {
        if let Some(p) = prep_init.registry.get(key) {
            println!("        ✓  {} {}  (né {}, NSS {})", p.prenom, p.nom, p.date_naissance, p.nss);
        }
    }

    node::write_intersection_csv(&matched, &prep_init.registry, "intersection_demo.csv").map_err(s)?;
    println!("\n[INIT] Résultat écrit : intersection_demo.csv");
    println!("[PART] Aucun résultat côté participant (par conception).");
    Ok(())
}

fn report(role: &str, p: &node::PreparedDataset) {
    println!("[{role}] {} patients uniques | {} doublon(s) | {} ligne(s) invalide(s)",
        p.keys.len(), p.duplicates_removed, p.invalid_rows.len());
    for (line, reason) in &p.invalid_rows {
        println!("        ⚠ ligne {line} ignorée : {reason}");
    }
}

fn roundtrip_kea_vec(v: &[KeaCt]) -> R<Vec<KeaCt>> {
    let bytes = codec::encode_kea_vec(v);
    codec::decode_kea_vec(&bytes).map_err(s)
}
fn roundtrip_buckets(b: &HashMap<usize, Vec<KeaCt>>) -> R<HashMap<usize, Vec<KeaCt>>> {
    let bytes = codec::encode_buckets(b);
    codec::decode_buckets(&bytes).map_err(s)
}
