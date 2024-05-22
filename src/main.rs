//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.

use std::sync::Arc;

use aes::{
    cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, Key, KeyInit},
    Aes128,
};
use rand::Rng;

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

fn main() {
    todo!("Maybe this should be a library crate. TBD");
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.encrypt_block(&mut block);

    block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.decrypt_block(&mut block);

    block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
    // When twe have a multiple the second term is 0
    let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

    for _ in 0..number_pad_bytes {
        data.push(number_pad_bytes as u8);
    }

    data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut block: [u8; BLOCK_SIZE] = Default::default();
        block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
        blocks.push(block);

        i += BLOCK_SIZE;
    }

    blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    let mut data = Vec::new();
    for block in blocks {
        data.extend_from_slice(&block);
    }
    data
}

/// Does the opposite of the pad function.
fn un_pad(data: Vec<u8>) -> Vec<u8> {
    let last_digit = *data.last().unwrap() as usize;
    let size = data.len();

    let mut data = data;

    if last_digit <= data.len() {
        let mut is_padded = true;
        for i in size - 1..size - last_digit {
            if data[i] != (last_digit as u8) {
                is_padded = false;
                break;
            }
        }
        if is_padded {
            data.truncate(data.len() - last_digit);
        }
    }
    data
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
    let mut cipher_text = Vec::new();
    let padded_groups = group(pad(plain_text));
    for block in padded_groups {
        let encrypted_block = aes_encrypt(block, &key);
        cipher_text.extend_from_slice(&encrypted_block);
    }
    cipher_text
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let padded_groups = group(cipher_text);
    let mut plaintext = Vec::new();
    for block in padded_groups {
        let decrypted_block = aes_decrypt(block, &key);
        plaintext.extend_from_slice(&decrypted_block);
    }
    un_pad(plaintext)
}

fn xor(a: &[u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random initialization vector for the first block.
    let iv = [0u8; BLOCK_SIZE];
    let padded_groups = group(pad(plain_text));
    let mut cipher_text = Vec::new();

    cipher_text.extend_from_slice(&iv);
    let mut prev_group = iv;

    for group in padded_groups {
        let xored_group = xor(&group, &prev_group);
        let encrypted_group = aes_encrypt(xored_group, &key);
        cipher_text.extend_from_slice(&encrypted_group);
        prev_group = encrypted_group;
    }

    cipher_text
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let encrypted_groups = group(cipher_text);
    let mut plaintext = Vec::new();

    let mut prev_group = encrypted_groups.first().unwrap();

    for i in 1..encrypted_groups.len() {
        let decrypted_block = aes_decrypt(encrypted_groups[i], &key);
        let xored_block = xor(&decrypted_block, &prev_group);
        plaintext.extend_from_slice(&xored_block);
        prev_group = &encrypted_groups[i];
    }

    un_pad(plaintext)
}

fn increment_byte_array(array: &mut Vec<u8>) {
    for i in 0..array.len() {
        array[i] += 1;
        if array[i] != 0 {
            break;
        }
        // integer overflow, update
    }
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random nonce
    let nonce = rand::thread_rng().gen::<[u8; BLOCK_SIZE / 2]>().to_vec();
    let mut counter = [0u8; BLOCK_SIZE / 2].to_vec();
    let mut cipher_text = Vec::new();
    let padded_groups = group(pad(plain_text));

    cipher_text.extend_from_slice(&pad(nonce.clone()));

    for group in padded_groups {
        let v = vec![nonce.clone(), counter.clone()].concat();
        let encrypted_v = aes_encrypt(v.as_slice().try_into().unwrap(), &key);
        let xored_block = xor(encrypted_v.as_slice().try_into().unwrap(), &group);
        cipher_text.extend_from_slice(&xored_block);

        increment_byte_array(&mut counter);
    }
    cipher_text
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let mut counter = [0u8; BLOCK_SIZE / 2].to_vec();
    let mut encrypted_groups = group(cipher_text);
    let nonce = encrypted_groups.remove(0); // remove nonce
    let nonce = nonce[0..BLOCK_SIZE / 2].to_vec();
    let mut plaintext = Vec::new();

    for group in encrypted_groups {
        let v = vec![nonce.clone(), counter.clone()].concat();
        let encrypted_v = aes_encrypt(v.as_slice().try_into().unwrap(), &key);
        let xored_block = xor(encrypted_v.as_slice().try_into().unwrap(), &group);
        plaintext.extend_from_slice(&xored_block);

        increment_byte_array(&mut counter);
    }
    un_pad(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad() {
        let data = vec![3, 2, 3, 1, 3, 2];
        let padded = pad(data);
        assert_eq!(padded[8], 10);
    }

    #[test]
    fn test_ecb() {
        let key = [0u8; 16];
        let plain_text = b"Hello, world!".to_vec();
        let cipher_text = super::ecb_encrypt(plain_text.clone(), key);
        let decrypted_text = super::ecb_decrypt(cipher_text, key);
        assert_eq!(plain_text, decrypted_text);
    }

    #[test]
    fn test_cbc() {
        let key = [0u8; 16];
        let plain_text = b"Hello, world!".to_vec();
        let cipher_text = super::cbc_encrypt(plain_text.clone(), key);
        let decrypted_text = super::cbc_decrypt(cipher_text, key);
        assert_eq!(plain_text, decrypted_text);
    }

    #[test]
    fn test_ctr() {
        let key = [0u8; 16];
        let plain_text = b"Hello, world!".to_vec();
        let cipher_text = super::ctr_encrypt(plain_text.clone(), key);
        let decrypted_text = super::ctr_decrypt(cipher_text, key);
        assert_eq!(plain_text, decrypted_text);
    }

    const TEST_KEY: [u8; 16] = [
        6, 108, 74, 203, 170, 212, 94, 238, 171, 104, 19, 17, 248, 197, 127, 138,
    ];

    #[test]
    fn ungroup_test() {
        let data: Vec<u8> = (0..48).collect();
        let grouped = group(data.clone());
        let ungrouped = un_group(grouped);
        assert_eq!(data, ungrouped);
    }

    #[test]
    fn unpad_test() {
        // An exact multiple of block size
        let data: Vec<u8> = (0..48).collect();
        let padded = pad(data.clone());
        let unpadded = un_pad(padded);
        assert_eq!(data, unpadded);

        // A non-exact multiple
        let data: Vec<u8> = (0..53).collect();
        let padded = pad(data.clone());
        let unpadded = un_pad(padded);
        assert_eq!(data, unpadded);
    }

    #[test]
    fn ecb_encrypt_test() {
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let encrypted = ecb_encrypt(plaintext, TEST_KEY);
        assert_eq!(
            "12d4105e43c4426e1f3e9455bb39c8fc0a4667637c9de8bad43ee801d313a555".to_string(),
            hex::encode(encrypted)
        );
    }

    #[test]
    fn ecb_decrypt_test() {
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext =
            hex::decode("12d4105e43c4426e1f3e9455bb39c8fc0a4667637c9de8bad43ee801d313a555")
                .unwrap();
        assert_eq!(plaintext, ecb_decrypt(ciphertext, TEST_KEY))
    }

    #[test]
    fn ecb_roundtrip_test() {
        // Because CBC uses randomness, the round trip has to be tested
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext = ecb_encrypt(plaintext.clone(), TEST_KEY);
        let decrypted = ecb_decrypt(ciphertext.clone(), TEST_KEY);
        assert_eq!(plaintext.clone(), decrypted);

        let mut modified_ciphertext = ciphertext.clone();
        modified_ciphertext[18] = 0;
        let decrypted_bad = ecb_decrypt(modified_ciphertext, TEST_KEY);
        assert_ne!(plaintext, decrypted_bad);
    }

    #[test]
    fn cbc_roundtrip_test() {
        // Because CBC uses randomness, the round trip has to be tested
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext = cbc_encrypt(plaintext.clone(), TEST_KEY);
        let decrypted = cbc_decrypt(ciphertext.clone(), TEST_KEY);
        assert_eq!(plaintext.clone(), decrypted);

        let mut modified_ciphertext = ciphertext.clone();
        modified_ciphertext[18] = 0;
        let decrypted_bad = cbc_decrypt(modified_ciphertext, TEST_KEY);
        assert_ne!(plaintext, decrypted_bad);
    }

    #[test]
    fn ctr_roundtrip_test() {
        // Because CBC uses randomness, the round trip has to be tested
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext = ctr_encrypt(plaintext.clone(), TEST_KEY);
        let decrypted = ctr_decrypt(ciphertext.clone(), TEST_KEY);
        assert_eq!(plaintext.clone(), decrypted);

        let mut modified_ciphertext = ciphertext.clone();
        modified_ciphertext[18] = 0;
        let decrypted_bad = ctr_decrypt(modified_ciphertext, TEST_KEY);
        assert_ne!(plaintext, decrypted_bad);
    }
}
