use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;

const LOCAL_ENCRYPTION_KEY: [u8; 32] = [
    0x85, 0x23, 0x6f, 0xb1, 0x9c, 0x08, 0x74, 0xd3, 0x2a, 0xe5, 0x41, 0x6b, 0x90, 0x37, 0xca, 0x14,
    0x5e, 0x68, 0xaf, 0xd2, 0x79, 0x03, 0xbc, 0x46, 0xf8, 0x1d, 0x57, 0xa0, 0x33, 0xee, 0x92, 0x6c,
];

pub fn encrypt(plaintext: &[u8], aad: &[u8]) -> Result<String, String> {
    let cipher =
        Aes256Gcm::new_from_slice(&LOCAL_ENCRYPTION_KEY).map_err(|error| error.to_string())?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "本地数据加密失败".to_string())?;
    let mut envelope = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
    envelope.push(1);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(STANDARD_NO_PAD.encode(envelope))
}

pub fn decrypt(encoded: &str, aad: &[u8]) -> Result<Vec<u8>, String> {
    let envelope = STANDARD_NO_PAD
        .decode(encoded)
        .map_err(|_| "本地密文格式无效".to_string())?;
    if envelope.len() < 14 || envelope[0] != 1 {
        return Err("本地密文版本无效".to_string());
    }
    let (nonce, ciphertext) = envelope[1..].split_at(12);
    let cipher =
        Aes256Gcm::new_from_slice(&LOCAL_ENCRYPTION_KEY).map_err(|error| error.to_string())?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "本地密文解密或完整性校验失败".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_ciphertext_to_its_domain() {
        let encrypted = encrypt(b"secret", b"shownet/domain-a").unwrap();
        assert_eq!(decrypt(&encrypted, b"shownet/domain-a").unwrap(), b"secret");
        assert!(decrypt(&encrypted, b"shownet/domain-b").is_err());
    }
}
