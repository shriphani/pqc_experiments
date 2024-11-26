use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hybrid_array::Array;
use ml_kem::kem::{DecapsulationKey, EncapsulationKey};
use ml_kem::MlKem768Params;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    KemCore, MlKem768,
};
use rand::rngs::OsRng;
use sha2::Sha256;

const K_CT_SIZE: usize = 1088;
const NONCE_SIZE: usize = 12;

fn main() {
    let mut rng = OsRng::default();
    let (dk, ek) = MlKem768::generate(&mut rng);

    let the_plaintext = b"go fuck yourself".to_vec();

    // sender generates ciphertext (anonymous) which is ct + ciphertex + authentication tag + nonce
    let ciphertext = sender_side(ek, the_plaintext.clone());

    // extract the plaintext
    let plaintext_recv = receiver_side(dk, &ciphertext);

    assert_eq!(the_plaintext, plaintext_recv);
}

fn sender_side(ek: EncapsulationKey<MlKem768Params>, plaintext: Vec<u8>) -> Vec<u8> {
    let mut rng = OsRng::default();

    // using public ek - generate a shared key (ct is encrypted shared key)
    let (k_ct, k_send) = ek.encapsulate(&mut rng).unwrap();

    // derive a key for a symmetric cipher
    let hkdf = Hkdf::<Sha256>::new(None, &k_send);

    let mut key = [0u8; 32];
    hkdf.expand(&[], &mut key).unwrap();

    // prepare the message:
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&[0u8; 12]);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .expect("Encryption failed");

    // the full payload is (ct || ciphertext || nonce)
    let mut payload = vec![];
    payload.extend_from_slice(&k_ct);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&nonce);

    payload
}

fn receiver_side(dk: DecapsulationKey<MlKem768Params>, payload: &[u8]) -> Vec<u8> {
    // extract ct, ciphertext, nonce
    let mut k_ct = [0_u8; K_CT_SIZE];

    k_ct.copy_from_slice(&payload[0..K_CT_SIZE]);

    let k_ct = Array::from_iter(k_ct);

    let ciphertext = &payload[K_CT_SIZE..payload.len() - NONCE_SIZE];
    let nonce = &payload[payload.len() - NONCE_SIZE..];

    // using private dk - obtain k
    let k_recv = dk.decapsulate(&k_ct).unwrap();

    // derive the key
    let hkdf = Hkdf::<Sha256>::new(None, &k_recv);

    let mut key = [0u8; 32];
    hkdf.expand(&[], &mut key).unwrap();

    // prepare the message:
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .unwrap();

    plaintext
}
