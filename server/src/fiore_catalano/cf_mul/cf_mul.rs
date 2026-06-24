use num_bigint::BigUint;
use dpeg_shared::paillier::p_encrypt::p_encrypt::p_encrypt;
use dpeg_shared::paillier::p_keygen::PublicKey;
use dpeg_shared::crypto_error::crypto_error::CryptoError;
use dpeg_shared::karatsuba_mul::karatsuba_mul::fast_mul;

// ---------------------------------------------------------------------------
// cf_mul — Multiplication homomorphique Catalano-Fiore
//
// Entrées : deux CF-chiffrés CF(m, r) = (c0, c1) et CF(m', r') = (c0', c1')
//   où  c0  = m  - r  mod n,   c1  = Enc(r)
//       c0' = m' - r' mod n,   c1' = Enc(r')
//
// Sortie  : un triplet (C0, C1, C2) tel que cf_mul_dec reconstruit m*m'.
//
// Algèbre Catalano-Fiore :
//   m * m' = (c0 + r)(c0' + r')
//           = c0*c0' + c0*r' + r*c0' + r*r'
//
//   On chiffre la partie déterministe (c0*c0') avec du bruit frais :
//     enc_prod = Enc(c0 * c0' mod n)
//
//   On masque avec les termes croisés (homomorphisme Paillier) :
//     C0 = enc_prod * c1'^{c0} * c1^{c0'}  mod ^2
//        = Enc(c0*c0' + r'*c0 + r*c0')
//
//   Le terme r*r' est récupéré lors du déchiffrement via C1 et C2 :
//     C1 = c1  = Enc(r)
//     C2 = c1' = Enc(r')
//
//   Déchiffrement (cf_mul_dec) :
//     Dec(C0) + Dec(C1)*Dec(C2) = (c0*c0' + r'*c0 + r*c0') + r*r'
//                                = m*m'  mod n  
// ---------------------------------------------------------------------------
pub fn cf_mul(
	ciphert:  &(BigUint, BigUint),
	ciphert1: &(BigUint, BigUint),
	pk:       &PublicKey,
) -> Result<(BigUint, BigUint, BigUint), CryptoError> {

	let c0   = &ciphert.0;    // m  - r  mod n
	let c1   = &ciphert.1;    // Enc(r)  dans Z_{n^2}

	let c0_p = &ciphert1.0;   // m' - r' mod n
	let c1_p = &ciphert1.1;   // Enc(r') dans Z_{n^2}

	// Étape 1 : chiffrer le produit des composantes plaintexts
	// product_c0 = c0 * c0' mod n   (plaintext -> modulus = n)

	let product_c0 = fast_mul(c0, c0_p, &pk.n)?;

	// enc_prod = Enc(c0 * c0') dans Z_{n^2}

	let enc_prod = p_encrypt(&product_c0, pk)?;

	// Étape 2 : termes croisés (exponentiations dans Z_{n^2}) 
	// c1^{c0'}  = Enc(r)^{c0'} = Enc(r * c0')   mod n^2
	
	let c1c0_p = c1.modpow(c0_p, &pk.n_squared);   // Enc(r * c0')

	// c1'^{c0} = Enc(r')^{c0} = Enc(r' * c0)   mod n^2

	let c1_pc0 = c1_p.modpow(c0, &pk.n_squared);   // Enc(r' * c0)

	//  Étape 3 : assemblage de C0 
	// C0 = enc_prod * c1'^{c0} * c1^{c0'}   mod n^2
	//    = Enc(c0*c0') * Enc(r'*c0) * Enc(r*c0')
	//    = Enc(c0*c0' + r'*c0 + r*c0')   mod n^2

	let step1 = fast_mul(&enc_prod, &c1_pc0, &pk.n_squared)?;  // enc_prod * c1'^{c0}
	let c0_res = fast_mul(&step1,   &c1c0_p, &pk.n_squared)?;  // step1    * c1^{c0'}

	// Étape 4 : conserver C1 et C2 pour le déchiffrement 
	// C1 = c1  = Enc(r),   C2 = c1' = Enc(r')
	// cf_mul_dec calculera r*r' = Dec(C1)*Dec(C2) et l'ajoutera à Dec(C0).
	
	let c1_res = c1.clone();
	let c2_res = c1_p.clone();

	Ok((c0_res, c1_res, c2_res))
}

