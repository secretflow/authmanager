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

use super::scheme::HmacScheme;
use auth_types::*;

#[allow(unreachable_patterns)]
pub fn generate_hmac(schema: HmacScheme, mac_key: &[u8], data: &[u8]) -> AuthResult<Vec<u8>> {
    // hmac
    let hmac_key = openssl::pkey::PKey::hmac(&mac_key)
        .map_err(|e| errno!(AuthStatus::InternalErr, "hmac init error: {:?}", e))?;
    let mut ctx = openssl::md_ctx::MdCtx::new()
        .map_err(|e| errno!(AuthStatus::InternalErr, "mdctx init error: {:?}", e))?;
    match schema {
        HmacScheme::SHA256 => {
            ctx.digest_sign_init(Some(openssl::md::Md::sha256()), &hmac_key)
                .map_err(|e| errno!(AuthStatus::InternalErr, "digest_sign_init error: {:?}", e))?;
        }
        HmacScheme::SM3 => {
            ctx.digest_sign_init(Some(openssl::md::Md::sm3()), &hmac_key)
                .map_err(|e| errno!(AuthStatus::InternalErr, "digest_sign_init error: {:?}", e))?;
        }
        _ => return_errno!(AuthStatus::InternalErr, "unsupported hmac schema"),
    }

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
    Ok(hmac)
}
