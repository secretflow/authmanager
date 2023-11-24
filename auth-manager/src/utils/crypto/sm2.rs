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

// because rust-openssl doesn't support sm2，we simply wrap openssl c-API
use super::{decrypter::Decrypter, encrypter::Encrypter, signer::Signer, verifier::Verifier};
use crate::utils::cvt_p;
use auth_types::*;
use libc::size_t;
use openssl_sys::*;
use std::os::raw::{c_int, c_void};
use std::ptr;

// NID_sm2: https://github.com/openssl/openssl/blob/master/include/openssl/obj_mac.h
const EVP_PKEY_SM2: i32 = 1172;

// The default sm2 id.
// Ref the last chapter of
// http://www.gmbz.org.cn/main/viewfile/2018011001400692565.html
const SM2_ID_DEFAULT: &str = "1234567812345678";

const EVP_PKEY_CTRL_SET1_ID: i32 = 0x1000 + 11;

const SM4_KEY_LENGTH: usize = 16;

const SM4_IV_LENGTH: usize = 16;

extern "C" {
    // OpenSSL documentation at [`EVP_PKEY_set_alias_type`].
    //
    // [EVP_PKEY_set_alias_type]: https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_set_alias_type.html
    pub fn EVP_PKEY_set_alias_type(pkey: *mut EVP_PKEY, ttype: c_int) -> c_int;

    pub fn EVP_MD_CTX_set_pkey_ctx(ctx: *mut EVP_MD_CTX, sctx: *mut EVP_PKEY_CTX) -> c_int;

    pub fn EVP_PKEY_CTX_ctrl(
        pctx: *mut EVP_PKEY_CTX,
        keytype: c_int,
        optype: c_int,
        cmd: c_int,
        p1: c_int,
        p2: *mut c_void,
    ) -> c_int;
}

pub struct PKey {
    evp_key: *mut EVP_PKEY,
}

impl Drop for PKey {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_free(self.evp_key);
        }
    }
}

struct BIOWapper {
    bio: *mut BIO,
}

impl Drop for BIOWapper {
    fn drop(&mut self) {
        unsafe {
            BIO_free_all(self.bio);
        }
    }
}
impl BIOWapper {
    pub fn as_ptr(&self) -> *mut BIO {
        self.bio
    }
}

struct EvpPkeyCtxWapper {
    evp_ctx: *mut EVP_PKEY_CTX,
}

impl Drop for EvpPkeyCtxWapper {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_CTX_free(self.evp_ctx);
        }
    }
}
impl EvpPkeyCtxWapper {
    pub fn as_ptr(&self) -> *mut EVP_PKEY_CTX {
        self.evp_ctx
    }
}

impl PKey {
    pub fn as_ptr(&self) -> *mut EVP_PKEY {
        self.evp_key
    }
    // Parse X509 `SubjectPublicKey` pem
    //
    // OpenSSL documentation at [`PEM_read_bio_PUBKEY`].
    //
    // [`PEM_read_bio_PUBKEY`]: https://www.openssl.org/docs/man1.1.1/man3/PEM_read_bio_PUBKEY.html
    pub fn public_key_from_pem(pem: &str) -> AuthResult<PKey> {
        unsafe {
            let bio = cvt_p(
                BIO_new_mem_buf(pem.as_ptr() as *const c_void, pem.len() as i32),
                "BIO_new_mem_buf failed.",
            )?;
            let bio_wapper = BIOWapper { bio };
            let evp_key = cvt_p(
                PEM_read_bio_PUBKEY(
                    bio_wapper.as_ptr(),
                    ptr::null_mut(),
                    Option::None,
                    ptr::null_mut(),
                ),
                "PEM_read_bio_PUBKEY failed.",
            )?;
            let pkey = PKey { evp_key };
            if EVP_PKEY_set_alias_type(pkey.as_ptr(), EVP_PKEY_SM2) != 1 {
                return_errno!(AuthStatus::CryptoErr, "EVP_PKEY_set_alias_type failed.");
            }
            Ok(pkey)
        }
    }

    // Parse PKCS#8 private key pem
    //
    // OpenSSL documentation at [`PEM_read_bio_PrivateKey`].
    //
    // [`PEM_read_bio_PrivateKey`]: https://www.openssl.org/docs/man1.1.1/man3/PEM_read_bio_PrivateKey.html
    pub fn private_key_from_pem(pem: &str) -> AuthResult<PKey> {
        unsafe {
            let bio = cvt_p(
                BIO_new_mem_buf(pem.as_ptr() as *const c_void, pem.len() as i32),
                "BIO_new_mem_buf failed.",
            )?;
            let bio_wapper = BIOWapper { bio };
            let evp_key = cvt_p(
                PEM_read_bio_PrivateKey(
                    bio_wapper.as_ptr(),
                    ptr::null_mut(),
                    Option::None,
                    ptr::null_mut(),
                ),
                "PEM_read_bio_PrivateKey failed.",
            )?;
            let pkey = PKey { evp_key };
            if EVP_PKEY_set_alias_type(pkey.as_ptr(), EVP_PKEY_SM2) != 1 {
                return_errno!(AuthStatus::CryptoErr, "EVP_PKEY_set_alias_type failed.");
            }
            Ok(pkey)
        }
    }
}

#[allow(unused)]
pub struct Sm2Encrypter {
    pctx: *mut EVP_PKEY_CTX,
    public_key: PKey,
}

impl Drop for Sm2Encrypter {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_CTX_free(self.pctx);
        }
    }
}

impl Sm2Encrypter {
    /// Creates a new `Sm2Encrypter`.
    ///
    /// OpenSSL documentation at [`EVP_PKEY_encrypt_init`].
    ///
    /// [`EVP_PKEY_encrypt_init`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_encrypt_init.html
    pub fn public_key_from_pem(pem: &str) -> AuthResult<Sm2Encrypter> {
        unsafe {
            let public_key = PKey::public_key_from_pem(pem)?;
            let pctx = cvt_p(
                EVP_PKEY_CTX_new(public_key.as_ptr(), ptr::null_mut()),
                "EVP_PKEY_CTX_new failed.",
            )?;
            let r = EVP_PKEY_encrypt_init(pctx);
            if r != 1 {
                EVP_PKEY_CTX_free(pctx);
                return_errno!(AuthStatus::CryptoErr, "EVP_PKEY_encrypt_init error");
            }

            Ok(Sm2Encrypter { pctx, public_key })
        }
    }
}

impl Encrypter for Sm2Encrypter {
    /// OpenSSL documentation at [`EVP_PKEY_encrypt`].
    ///
    /// [`EVP_PKEY_encrypt`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_encrypt.html
    fn encrypt(&self, data: &[u8]) -> AuthResult<Vec<u8>> {
        unsafe {
            let mut ciphertext_len: size_t = 0;
            // get length
            if EVP_PKEY_encrypt(
                self.pctx,
                ptr::null_mut(),
                &mut ciphertext_len as *mut size_t,
                data.as_ptr(),
                data.len(),
            ) < 0
            {
                return_errno!(AuthStatus::CryptoErr, "EVP_PKEY_encrypt failed.");
            }
            // the cipher_text size should be defined after length initialization
            let mut cipher_text = vec![0u8; ciphertext_len];
            if EVP_PKEY_encrypt(
                self.pctx,
                cipher_text.as_mut_ptr(),
                &mut ciphertext_len as *mut size_t,
                data.as_ptr(),
                data.len(),
            ) < 0
            {
                return_errno!(AuthStatus::CryptoErr, "EVP_PKEY_encrypt failed.");
            }
            let mut result_vec = cipher_text.to_vec();
            result_vec.truncate(ciphertext_len);
            Ok(result_vec)
        }
    }

    fn seal_digital_envelope(
        &self,
        data: &[u8],
    ) -> AuthResult<auth_manager_tonic::sdc::AsymmetricSecret> {
        let mut sm4_key = [0u8; SM4_KEY_LENGTH];
        let mut iv = [0u8; SM4_IV_LENGTH];
        let add: Vec<u8> = Vec::new();
        openssl::rand::rand_bytes(&mut sm4_key)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "rand sm4 key failed: {:?}", e))?;
        openssl::rand::rand_bytes(&mut iv)
            .map_err(|e| errno!(AuthStatus::CryptoErr, "rand iv failed: {:?}", e))?;
        let asymmetric_encrypted_key = self.encrypt(&sm4_key)?;
        // SM4 encrypt
        let cipher =
            openssl::symm::encrypt(openssl::symm::Cipher::sm4_cbc(), &sm4_key, Some(&iv), data)
                .map_err(|e| errno!(AuthStatus::InternalErr, "sm4 encrypt error: {:?}", e))?;

        // hmac
        let hmac_key = openssl::pkey::PKey::hmac(&sm4_key)
            .map_err(|e| errno!(AuthStatus::InternalErr, "hmac init error: {:?}", e))?;
        let mut ctx = openssl::md_ctx::MdCtx::new()
            .map_err(|e| errno!(AuthStatus::InternalErr, "mdctx init error: {:?}", e))?;
        ctx.digest_sign_init(Some(openssl::md::Md::sm3()), &hmac_key)
            .map_err(|e| errno!(AuthStatus::InternalErr, "digest_sign_init error: {:?}", e))?;
        ctx.digest_sign_update(data)
            .map_err(|e| errno!(AuthStatus::InternalErr, "digest_sign_update error: {:?}", e))?;
        let mut hmac = vec![];
        ctx.digest_sign_final_to_vec(&mut hmac).map_err(|e| {
            errno!(
                AuthStatus::InternalErr,
                "digest_sign_final_to_vec error: {:?}",
                e
            )
        })?;
        Ok(auth_manager_tonic::sdc::AsymmetricSecret {
            asymmetric_encrypted_key,
            symmetric_secret: Some(auth_manager_tonic::sdc::SymmetricSecret {
                encrypted_data: cipher,
                encrypted_data_cmac: hmac,
                initial_vector: iv.to_vec(),
                additional_authentication_data: add.to_vec(),
            }),
        })
    }
}

#[allow(unused)]
pub struct Sm2Decrypter {
    pctx: *mut EVP_PKEY_CTX,
    private_key: PKey,
}

impl Drop for Sm2Decrypter {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_CTX_free(self.pctx);
        }
    }
}

impl Sm2Decrypter {
    /// Creates a new `Sm2Decrypter`.
    ///
    /// OpenSSL documentation at [`EVP_PKEY_decrypt_init`].
    ///
    /// [`EVP_PKEY_decrypt_init`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_decrypt_init.html
    pub fn private_key_from_pem(pem: &str) -> AuthResult<Sm2Decrypter> {
        unsafe {
            let private_key = PKey::private_key_from_pem(pem)?;
            let pctx = cvt_p(
                EVP_PKEY_CTX_new(private_key.as_ptr(), ptr::null_mut()),
                "EVP_PKEY_CTX_new failed.",
            )?;
            let r = EVP_PKEY_decrypt_init(pctx);
            if r != 1 {
                EVP_PKEY_CTX_free(pctx);
                return_errno!(AuthStatus::CryptoErr, "EVP_PKEY_decrypt_init error");
            }
            Ok(Sm2Decrypter { pctx, private_key })
        }
    }
}

impl Decrypter for Sm2Decrypter {
    /// OpenSSL documentation at [`EVP_PKEY_decrypt`].
    ///
    /// [`EVP_PKEY_decrypt`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_decrypt.html
    fn decrypt(&self, data: &[u8]) -> AuthResult<Vec<u8>> {
        unsafe {
            let mut plaintext_len: size_t = 0;
            // get length
            if EVP_PKEY_decrypt(
                self.pctx,
                ptr::null_mut(),
                &mut plaintext_len as *mut size_t,
                data.as_ptr(),
                data.len(),
            ) < 0
            {
                return_errno!(AuthStatus::CryptoErr, "EVP_PKEY_decrypt failed.");
            }
            // The cipher_text size should be defined after length initialization
            let mut plaintext = vec![0u8; plaintext_len];
            if EVP_PKEY_decrypt(
                self.pctx,
                plaintext.as_mut_ptr(),
                &mut plaintext_len as *mut size_t,
                data.as_ptr(),
                data.len(),
            ) < 0
            {
                return_errno!(AuthStatus::CryptoErr, "EVP_PKEY_decrypt failed.");
            }
            let mut result_vec = plaintext.to_vec();
            result_vec.truncate(plaintext_len);

            Ok(result_vec)
        }
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
        if iv.len() != SM4_IV_LENGTH {
            return_errno!(AuthStatus::InternalErr, "iv length is not equal to 16.")
        }

        let tag = &symmetric_secret.encrypted_data_cmac;
        let cipher = &symmetric_secret.encrypted_data;
        let sm4_key = self.decrypt(&asymmetric_encrypted_key)?;
        if sm4_key.len() != SM4_KEY_LENGTH {
            return_errno!(
                AuthStatus::InternalErr,
                "sm4_key length is not equal to 16."
            )
        }
        let plaintext =
            openssl::symm::decrypt(openssl::symm::Cipher::sm4_cbc(), &sm4_key, Some(iv), cipher)
                .map_err(|e| errno!(AuthStatus::CryptoErr, "sm4 decrypt error: {:?}", e))?;

        // hmac
        let hmac_key = openssl::pkey::PKey::hmac(&sm4_key)
            .map_err(|e| errno!(AuthStatus::InternalErr, "hmac init error: {:?}", e))?;
        let mut ctx = openssl::md_ctx::MdCtx::new()
            .map_err(|e| errno!(AuthStatus::InternalErr, "mdctx init error: {:?}", e))?;
        ctx.digest_sign_init(Some(openssl::md::Md::sm3()), &hmac_key)
            .map_err(|e| errno!(AuthStatus::InternalErr, "digest_sign_init error: {:?}", e))?;
        ctx.digest_sign_update(&plaintext)
            .map_err(|e| errno!(AuthStatus::InternalErr, "digest_sign_update error: {:?}", e))?;
        let mut hmac = vec![];
        ctx.digest_sign_final_to_vec(&mut hmac).map_err(|e| {
            errno!(
                AuthStatus::InternalErr,
                "digest_sign_final_to_vec error: {:?}",
                e
            )
        })?;
        auth_assert!(tag == &hmac, "tag mismatch");
        Ok(plaintext)
    }
}

#[allow(unused)]
pub struct Sm2Signer {
    md_ctx: *mut EVP_MD_CTX,
    evp_ctx: EvpPkeyCtxWapper,
    private_key: PKey,
}

impl Sm2Signer {
    /// Creates a new `Sm2Signer`.
    ///
    /// OpenSSL documentation at [`EVP_DigestSignInit`].
    ///
    /// [`EVP_DigestSignInit`]: https://www.openssl.org/docs/manmaster/man3/EVP_DigestSignInit.html
    pub fn private_key_from_pem(pem: &str) -> AuthResult<Sm2Signer> {
        unsafe {
            let private_key = PKey::private_key_from_pem(pem)?;
            let md_ctx = cvt_p(EVP_MD_CTX_new(), "EVP_MD_CTX_new failed.")?;
            let pctx = cvt_p(
                EVP_PKEY_CTX_new(private_key.as_ptr(), ptr::null_mut()),
                "EVP_PKEY_CTX_new failed.",
            )?;
            let evp_ctx = EvpPkeyCtxWapper { evp_ctx: pctx };
            let mut id = SM2_ID_DEFAULT.to_owned();

            auth_assert!(
                EVP_PKEY_CTX_ctrl(
                    evp_ctx.as_ptr(),
                    -1,
                    -1,
                    EVP_PKEY_CTRL_SET1_ID,
                    SM2_ID_DEFAULT.len() as i32,
                    id.as_mut_ptr() as *mut _,
                ) > 0,
                "EVP_PKEY_CTX_ctrl error"
            );

            EVP_MD_CTX_set_pkey_ctx(md_ctx, evp_ctx.as_ptr());

            let r = EVP_DigestSignInit(
                md_ctx,
                ptr::null_mut(),
                EVP_sm3(),
                ptr::null_mut(),
                ptr::null_mut(),
            );

            if r != 1 {
                EVP_MD_CTX_free(md_ctx);
                return_errno!(AuthStatus::CryptoErr, "EVP_DigestSignInit error");
            }
            auth_assert!(!pctx.is_null(), "pctx is null");

            Ok(Sm2Signer {
                md_ctx,
                evp_ctx,
                private_key,
            })
        }
    }
}

impl Drop for Sm2Signer {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_CTX_free(self.md_ctx);
        }
    }
}

impl Signer for Sm2Signer {
    fn sign(&self, data: &[u8]) -> AuthResult<Vec<u8>> {
        unsafe {
            auth_assert!(
                EVP_DigestUpdate(self.md_ctx, data.as_ptr() as *const _, data.len(),) > 0,
                "EVP_DigestUpdate failed."
            );

            let mut len = 0;

            auth_assert!(
                EVP_DigestSignFinal(self.md_ctx, ptr::null_mut(), &mut len,) > 0,
                "EVP_DigestSignFinal failed."
            );

            let mut sig = vec![0u8; len];
            auth_assert!(
                EVP_DigestSignFinal(self.md_ctx, sig.as_mut_ptr(), &mut len,) > 0,
                "EVP_DigestSignFinal failed."
            );
            sig.truncate(len);
            return Ok(sig);
        }
    }
}

#[allow(unused)]
pub struct Sm2Verifier {
    md_ctx: *mut EVP_MD_CTX,
    evp_ctx: EvpPkeyCtxWapper,
    public_key: PKey,
}

impl Sm2Verifier {
    /// Creates a new `Sm2Verifier`.
    ///
    /// OpenSSL documentation at [`EVP_DigestVerifyInit`].
    ///
    /// [`EVP_DigestVerifyInit`]: https://www.openssl.org/docs/manmaster/man3/EVP_DigestVerifyInit.html
    pub fn public_key_from_pem(pem: &str) -> AuthResult<Sm2Verifier> {
        unsafe {
            let public_key = PKey::public_key_from_pem(pem)?;
            let md_ctx = cvt_p(EVP_MD_CTX_new(), "EVP_MD_CTX_new failed.")?;
            let pctx = cvt_p(
                EVP_PKEY_CTX_new(public_key.as_ptr(), ptr::null_mut()),
                "EVP_PKEY_CTX_new failed.",
            )?;
            let evp_ctx = EvpPkeyCtxWapper { evp_ctx: pctx };
            let mut id = SM2_ID_DEFAULT.to_owned();

            auth_assert!(
                EVP_PKEY_CTX_ctrl(
                    evp_ctx.as_ptr(),
                    -1,
                    -1,
                    EVP_PKEY_CTRL_SET1_ID,
                    SM2_ID_DEFAULT.len() as i32,
                    id.as_mut_ptr() as *mut _,
                ) > 0,
                "EVP_PKEY_CTX_ctrl error"
            );

            EVP_MD_CTX_set_pkey_ctx(md_ctx, evp_ctx.as_ptr());

            let r = EVP_DigestVerifyInit(
                md_ctx,
                ptr::null_mut(),
                EVP_sm3(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if r != 1 {
                return_errno!(AuthStatus::CryptoErr, "EVP_DigestVerifyInit error");
            }
            Ok(Sm2Verifier {
                md_ctx,
                evp_ctx,
                public_key,
            })
        }
    }
}

impl Drop for Sm2Verifier {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_CTX_free(self.md_ctx);
        }
    }
}

impl Verifier for Sm2Verifier {
    fn verifier(&self, data: &[u8], signature: &[u8]) -> AuthResult<bool> {
        unsafe {
            auth_assert!(
                EVP_DigestUpdate(self.md_ctx, data.as_ptr() as *const _, data.len(),) > 0,
                "EVP_DigestUpdate failed."
            );
            let r =
                EVP_DigestVerifyFinal(self.md_ctx, signature.as_ptr() as *mut _, signature.len());
            match r {
                1 => Ok(true),
                0 => Ok(false),
                _ => Err(errno!(
                    AuthStatus::CryptoErr,
                    "EVP_DigestVerifyFinal failed."
                )),
            }
        }
    }
}
