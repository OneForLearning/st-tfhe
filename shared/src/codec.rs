// ============================================================================
//  shared/src/codec.rs — Sérialisation transport-agnostique (KEA)
//
//  ⚠ AUCUNE I/O réseau ici. Convertit les structures du protocole en Vec<u8>
//  et inversement. Depuis le passage à KEA (Paillier P²), un chiffré est une
//  PAIRE (Enc(m), Enc(ψ·m)) → KeaCt. Edb, buckets, Eres, Echeck transportent
//  donc des paires.
//
//  Le backend utilise ces helpers (ou son propre format) pour acheminer les
//  données. Données qui traversent le réseau :
//    pk, ct_delta (paire), N, EDB (paires), Eres (paires), buckets (paires),
//    Echeck (paires), MatchedPos (positions), counts.
// ============================================================================

use std::collections::HashMap;
use std::io::{self, Cursor, Read};

use num_bigint::BigUint;
use crate::exactmatch::types::KeaCt;

// ── Primitifs entiers (big-endian) ───────────────────────────────────────────
fn put_u32(out: &mut Vec<u8>, v: u32) { out.extend_from_slice(&v.to_be_bytes()); }
fn put_u64(out: &mut Vec<u8>, v: u64) { out.extend_from_slice(&v.to_be_bytes()); }
fn get_u32<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4]; r.read_exact(&mut b)?; Ok(u32::from_be_bytes(b))
}
fn get_u64<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut b = [0u8; 8]; r.read_exact(&mut b)?; Ok(u64::from_be_bytes(b))
}

// ── BigUint : [u32 longueur][octets big-endian] ──────────────────────────────
pub fn encode_biguint(n: &BigUint) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    let mut out = Vec::with_capacity(4 + bytes.len());
    put_u32(&mut out, bytes.len() as u32);
    out.extend_from_slice(&bytes);
    out
}
fn read_biguint<R: Read>(r: &mut R) -> io::Result<BigUint> {
    let len = get_u32(r)? as usize;
    let mut bytes = vec![0u8; len];
    r.read_exact(&mut bytes)?;
    Ok(BigUint::from_bytes_be(&bytes))
}
pub fn decode_biguint<R: Read>(r: &mut R) -> io::Result<BigUint> { read_biguint(r) }

// ── Chiffré KEA : paire (c0, c1) ─────────────────────────────────────────────
pub fn encode_kea_ct(ct: &KeaCt) -> Vec<u8> {
    let mut out = encode_biguint(&ct.0);
    out.extend(encode_biguint(&ct.1));
    out
}
fn read_kea_ct<R: Read>(r: &mut R) -> io::Result<KeaCt> {
    let c0 = read_biguint(r)?;
    let c1 = read_biguint(r)?;
    Ok((c0, c1))
}
pub fn decode_kea_ct(buf: &[u8]) -> io::Result<KeaCt> { read_kea_ct(&mut Cursor::new(buf)) }

// ── ct_delta (paire publique) — même format qu'un KeaCt ──────────────────────
pub fn encode_ct_delta(d: &KeaCt) -> Vec<u8> { encode_kea_ct(d) }
pub fn decode_ct_delta(buf: &[u8]) -> io::Result<KeaCt> { decode_kea_ct(buf) }

// ── Clé publique : (n, g, n²) ────────────────────────────────────────────────
pub fn encode_pk(n: &BigUint, g: &BigUint, n_squared: &BigUint) -> Vec<u8> {
    let mut out = encode_biguint(n);
    out.extend(encode_biguint(g));
    out.extend(encode_biguint(n_squared));
    out
}
pub fn decode_pk(buf: &[u8]) -> io::Result<(BigUint, BigUint, BigUint)> {
    let mut cur = Cursor::new(buf);
    Ok((read_biguint(&mut cur)?, read_biguint(&mut cur)?, read_biguint(&mut cur)?))
}

// ── Vec<KeaCt> : EDB, Eres, Echeck ─ [u32 count][kea_ct…] ────────────────────
pub fn encode_kea_vec(v: &[KeaCt]) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, v.len() as u32);
    for ct in v { out.extend(encode_kea_ct(ct)); }
    out
}
pub fn decode_kea_vec(buf: &[u8]) -> io::Result<Vec<KeaCt>> {
    let mut cur = Cursor::new(buf);
    let n = get_u32(&mut cur)? as usize;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n { v.push(read_kea_ct(&mut cur)?); }
    Ok(v)
}

// ── Buckets : HashMap<usize, Vec<KeaCt>> ─────────────────────────────────────
// [u32 nb_positions]  puis pour chaque : [u64 pos][u32 nb_ct][kea_ct…]
pub fn encode_buckets(b: &HashMap<usize, Vec<KeaCt>>) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, b.len() as u32);
    let mut keys: Vec<usize> = b.keys().copied().collect();
    keys.sort();
    for p in keys {
        let v = &b[&p];
        put_u64(&mut out, p as u64);
        put_u32(&mut out, v.len() as u32);
        for ct in v { out.extend(encode_kea_ct(ct)); }
    }
    out
}
pub fn decode_buckets(buf: &[u8]) -> io::Result<HashMap<usize, Vec<KeaCt>>> {
    let mut cur = Cursor::new(buf);
    let nb = get_u32(&mut cur)? as usize;
    let mut map = HashMap::with_capacity(nb);
    for _ in 0..nb {
        let p = get_u64(&mut cur)? as usize;
        let k = get_u32(&mut cur)? as usize;
        let mut v = Vec::with_capacity(k);
        for _ in 0..k { v.push(read_kea_ct(&mut cur)?); }
        map.insert(p, v);
    }
    Ok(map)
}

// ── Vec<usize> : MatchedPos ─ [u32 count][u64…] ──────────────────────────────
pub fn encode_pos(pos: &[usize]) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, pos.len() as u32);
    for &p in pos { put_u64(&mut out, p as u64); }
    out
}
pub fn decode_pos(buf: &[u8]) -> io::Result<Vec<usize>> {
    let mut cur = Cursor::new(buf);
    let n = get_u32(&mut cur)? as usize;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n { v.push(get_u64(&mut cur)? as usize); }
    Ok(v)
}

// ── Counts : HashMap<usize, usize> ─ [u32 nb][u64 pos][u64 count]… ───────────
pub fn encode_counts(c: &HashMap<usize, usize>) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, c.len() as u32);
    let mut keys: Vec<usize> = c.keys().copied().collect();
    keys.sort();
    for p in keys { put_u64(&mut out, p as u64); put_u64(&mut out, c[&p] as u64); }
    out
}
pub fn decode_counts(buf: &[u8]) -> io::Result<HashMap<usize, usize>> {
    let mut cur = Cursor::new(buf);
    let nb = get_u32(&mut cur)? as usize;
    let mut map = HashMap::with_capacity(nb);
    for _ in 0..nb {
        let p = get_u64(&mut cur)? as usize;
        let v = get_u64(&mut cur)? as usize;
        map.insert(p, v);
    }
    Ok(map)
}

// ── usize seul (N négocié) ───────────────────────────────────────────────────
pub fn encode_usize(v: usize) -> Vec<u8> { let mut o = Vec::new(); put_u64(&mut o, v as u64); o }
pub fn decode_usize(buf: &[u8]) -> io::Result<usize> {
    let mut cur = Cursor::new(buf); Ok(get_u64(&mut cur)? as usize)
}
