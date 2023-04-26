// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::utils::crypto::{
    decrypter::Decrypter, encrypter::Encrypter, signer::Signer, verifier::Verifier,
};
use auth_types::*;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;

/// AES-128-GCM params
// AES key length is 128 bit(16 byte)
const AES_KEY_LENGTH: usize = 16;
// initial vector length is 96 bit(12 byte)
const IV_LENGTH: usize = 12;
// https://en.wikipedia.org/wiki/Authenticated_encryption
// authentication tag (GMAC),length is 128 bit(16 byte)
const TAG_LENGTH: usize = 16;

pub struct RsaPublicKeyHolder {
    public_key: PKey<Public>,
}

impl RsaPublicKeyHolder {
    // Parse X509 `SubjectPublicKey` pem
    pub fn public_key_from_pem(pem: &str) -> AuthResult<RsaPublicKeyHolder> {
        let public_key = PKey::public_key_from_pem(pem.as_bytes()).map_err(|e| {
            errno!(
                AuthStatus::CryptoErr,
                "parse X509 public key error: {:?}",
                e
            )
        })?;
        Ok(RsaPublicKeyHolder { public_key })
    }

    // Parse pkcs#1 public key pem
    pub fn public_key_from_pem_pkcs1(pem: &str) -> AuthResult<RsaPublicKeyHolder> {
        let public_key = Rsa::public_key_from_pem_pkcs1(pem.as_bytes()).map_err(|e| {
            errno!(
                AuthStatus::CryptoErr,
                "parse pkcs#1 public key error: {:?}",
                e
            )
        })?;
        let public_key = PKey::from_rsa(public_key)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "convert rsa to pkey error:{:?}", e))?;
        Ok(RsaPublicKeyHolder { public_key })
    }
}

impl Encrypter for RsaPublicKeyHolder {
    // RSA encrypt with PKCS1_OAEP padding
    fn encrypt(&self, data: &[u8]) -> AuthResult<Vec<u8>> {
        // Encrypt the data with RSA PKCS1
        let mut encrypter = openssl::encrypt::Encrypter::new(&self.public_key)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "encrypter init error: {:?}", e))?;
        // Set RSA padding
        encrypter
            .set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "set rsa padding error: {}", e))?;
        // Create an output buffer
        let buffer_len = encrypter
            .encrypt_len(data)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "get cipher_text length error: {}", e))?;
        let mut encrypted = vec![0; buffer_len];
        // Encrypt and truncate the buffer
        let encrypted_len = encrypter
            .encrypt(data, &mut encrypted)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "encrypt error: {:?}", e))?;
        encrypted.truncate(encrypted_len);
        Ok(encrypted)
    }

    fn seal_digital_envelope(
        &self,
        data: &[u8],
    ) -> AuthResult<auth_manager_tonic::sdc::AsymmetricSecret> {
        let mut aes_key = [0u8; AES_KEY_LENGTH];
        let mut iv = [0u8; IV_LENGTH];
        let add: Vec<u8> = Vec::new();
        let mut tag = [0u8; TAG_LENGTH];

        openssl::rand::rand_bytes(&mut aes_key)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "rand aes key failed: {:?}", e))?;
        openssl::rand::rand_bytes(&mut iv)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "rand iv failed: {:?}", e))?;

        let asymmetric_encrypted_key = self.encrypt(&aes_key)?;
        let cipher = openssl::symm::encrypt_aead(
            openssl::symm::Cipher::aes_128_gcm(),
            &aes_key,
            Some(&iv),
            &add,
            data,
            &mut tag,
        )
        .map_err(|e| errno!(AuthStatus::InternalErr, "aes encrypt error: {:?}", e))?;

        Ok(auth_manager_tonic::sdc::AsymmetricSecret {
            asymmetric_encrypted_key,
            symmetric_secret: Some(auth_manager_tonic::sdc::SymmetricSecret {
                encrypted_data: cipher,
                encrypted_data_cmac: tag.to_vec(),
                initial_vector: iv.to_vec(),
                additional_authentication_data: add.to_vec(),
            }),
        })
    }
}

pub struct RsaPrivateKeyHolder {
    private_key: PKey<Private>,
}

impl RsaPrivateKeyHolder {
    // Parse pkcs#8 private key pem
    pub fn private_key_from_pem(pem: &str) -> AuthResult<RsaPrivateKeyHolder> {
        let private_key = PKey::private_key_from_pem(pem.as_bytes()).map_err(|e| {
            errno!(
                AuthStatus::CryptoErr,
                "parse pkcs#8 private key error: {:?}",
                e
            )
        })?;
        Ok(RsaPrivateKeyHolder { private_key })
    }
    // Parse pkcs#1 private key pem
    pub fn private_key_from_pem_pkcs1(pem: &str) -> AuthResult<RsaPrivateKeyHolder> {
        let private_key = Rsa::private_key_from_pem(pem.as_bytes()).map_err(|e| {
            errno!(
                AuthStatus::CryptoErr,
                "parse pkcs#1 private key error: {:?}",
                e
            )
        })?;
        let private_key = PKey::from_rsa(private_key)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "convert rsa to pkey error: {}", e))?;
        Ok(RsaPrivateKeyHolder { private_key })
    }
}

impl Decrypter for RsaPrivateKeyHolder {
    // RSA decrypt with PKCS1_OAEP padding
    fn decrypt(&self, encrypted: &[u8]) -> AuthResult<Vec<u8>> {
        // Decrypt the data
        let mut decrypter = openssl::encrypt::Decrypter::new(&self.private_key)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "decrypter init error: {}", e))?;
        decrypter
            .set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "set rsa padding error: {}", e))?;
        // Create an output buffer
        let buffer_len = decrypter
            .decrypt_len(&encrypted)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "get plain_text length error: {}", e))?;
        let mut decrypted = vec![0u8; buffer_len];
        // Encrypt and truncate the buffer
        let decrypted_len = decrypter
            .decrypt(&encrypted, &mut decrypted)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "decrypt error: {}", e))?;
        decrypted.truncate(decrypted_len);
        Ok(decrypted)
    }

    fn open_digital_envelope(
        &self,
        envelope: &auth_manager_tonic::sdc::AsymmetricSecret,
    ) -> AuthResult<Vec<u8>> {
        let asymmetric_encrypted_key = &envelope.asymmetric_encrypted_key;
        let symmetric_secret = match &envelope.symmetric_secret {
            Some(ss) => ss,
            None => return_errno!(
                AuthStatus::InternalErr,
                "envelope.symmetric_secret is empty"
            ),
        };

        let iv = &symmetric_secret.initial_vector;
        if iv.len() != IV_LENGTH {
            return_errno!(AuthStatus::InternalErr, "iv length is not equal to 12.")
        }
        let add = &symmetric_secret.additional_authentication_data;
        let tag = &symmetric_secret.encrypted_data_cmac;
        if tag.len() != TAG_LENGTH {
            return_errno!(AuthStatus::InternalErr, "tag length is not equal to 16.")
        }
        let cipher = &symmetric_secret.encrypted_data;
        let aes_key = self.decrypt(&asymmetric_encrypted_key)?;
        if aes_key.len() != AES_KEY_LENGTH {
            return_errno!(
                AuthStatus::InternalErr,
                "aes_key length is not equal to 16."
            )
        }
        let plaintext = openssl::symm::decrypt_aead(
            openssl::symm::Cipher::aes_128_gcm(),
            &aes_key,
            Some(iv),
            &add,
            cipher,
            tag,
        )
        .map_err(|e| errno!(AuthStatus::CryptoErr, "aes decrypt error: {:?}", e))?;
        Ok(plaintext)
    }
}

impl Signer for RsaPrivateKeyHolder {
    fn sign(&self, data: &[u8]) -> AuthResult<Vec<u8>> {
        use openssl::hash::MessageDigest;
        let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &self.private_key)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "signer create error: {:?}", e))?;
        signer
            .update(data)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "update msg error: {:?}", e))?;
        let sig = signer
            .sign_to_vec()
            .map_err(|e| errno!(AuthStatus::CryptoErr, "sign msg error: {:?}", e))?;
        Ok(sig)
    }
}

impl Verifier for RsaPublicKeyHolder {
    fn verifier(&self, data: &[u8], signature: &[u8]) -> AuthResult<bool> {
        use openssl::hash::MessageDigest;
        let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha256(), &self.public_key)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "verifier create error: {:?}", e))?;
        verifier
            .update(data)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "update msg error: {:?}", e))?;
        let res = verifier
            .verify(signature)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "verify signature error: {:?}", e))?;
        Ok(res)
    }
}
