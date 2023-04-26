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

pub mod decrypter;
pub mod encrypter;
pub mod hmac;
pub mod rsa;
pub mod scheme;
pub mod sha;
pub mod signer;
pub mod sm2;
pub mod verifier;

#[cfg(test)]
mod test {
    use openssl::rsa::Rsa;

    use crate::utils::crypto::rsa::{RsaPrivateKeyHolder, RsaPublicKeyHolder};
    use crate::utils::crypto::signer::Signer;
    use crate::utils::crypto::verifier::Verifier;
    use crate::utils::crypto::{decrypter::Decrypter, encrypter::Encrypter};
    use std::str;

    #[test]
    fn rsa() {
        let rsa = Rsa::generate(3072).expect("create rsa key pair failed");
        let rsa_public_key_pem = rsa.public_key_to_pem().unwrap();
        let rsa_private_key_pem = rsa.private_key_to_pem().unwrap();

        let buffer = "hello".as_bytes();
        let encryptor =
            RsaPublicKeyHolder::public_key_from_pem(str::from_utf8(&rsa_public_key_pem).unwrap())
                .unwrap();

        let decryptor = RsaPrivateKeyHolder::private_key_from_pem(
            str::from_utf8(&rsa_private_key_pem).unwrap(),
        )
        .unwrap();

        let enc_data = encryptor.encrypt(buffer).unwrap();
        let dec_data = decryptor.decrypt(&enc_data).unwrap();
        assert_eq!(buffer, dec_data);
    }

    #[test]
    fn rsa_sign_verify() {
        let rsa = Rsa::generate(3072).expect("create rsa key pair failed");
        let rsa_public_key_pem = rsa.public_key_to_pem_pkcs1().unwrap();
        let rsa_private_key_pem = rsa.private_key_to_pem().unwrap();
        let buffer = "hello".as_bytes();
        let verifier = RsaPublicKeyHolder::public_key_from_pem_pkcs1(
            str::from_utf8(&rsa_public_key_pem).unwrap(),
        )
        .unwrap();

        let signer = RsaPrivateKeyHolder::private_key_from_pem_pkcs1(
            str::from_utf8(&rsa_private_key_pem).unwrap(),
        )
        .unwrap();
        let signature = signer.sign(buffer).unwrap();
        assert!(verifier.verifier(buffer, &signature).unwrap());
    }
}
