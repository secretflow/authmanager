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

use std::str::FromStr;

use crate::utils::crypto::{
    decrypter::Decrypter,
    encrypter::Encrypter,
    rsa::{RsaPrivateKeyHolder, RsaPublicKeyHolder},
    scheme::AsymmetricScheme,
    sm2::{Sm2Decrypter, Sm2Encrypter},
};
use auth_manager_tonic::sdc::{
    authmanager::GetExportDataKeyRequest, dataagent::*, segment_data_uri::OptionalSeg,
    SegmentDataMeta,
};
use auth_types::*;

use super::AuthManagerImpl;

impl AuthManagerImpl {
    pub async fn get_export_data_key_impl(
        &self,
        request: GetExportDataKeyRequest,
    ) -> AuthResult<Vec<SegmentDataMeta>> {
        let req = GetPartitionAccessInfoRequest {
            header: Some(auth_manager_tonic::RequestHeader::default()),
            partition_id_infos: vec![PartitionIdInfo {
                data_uuid: request.data_uuid.clone(),
                partition_id: request.partition_id.clone(),
                partition_expr: "".to_owned(),
            }],
        };

        // sanity check
        let resp: GetDataAccessInfoResponse =
            self.storage_client.get_partition_access_info(req).await?;
        if resp.data_uri_with_dk.len() != 1 {
            return_errno!(AuthStatus::InternalErr, "data_uri_with_dk.len should be 1.");
        }
        let data_uri = &resp.data_uri_with_dk[0];
        if data_uri.data_uuid != request.data_uuid {
            return_errno!(
                AuthStatus::InternalErr,
                "data uuid mismatching, request.data_uuid: {}, data_uri.data_uuid: {}",
                request.data_uuid,
                data_uri.data_uuid
            );
        }
        if data_uri.part_data_uris.len() != 1 {
            return_errno!(
                AuthStatus::InternalErr,
                "data_uri.part_data_uris.len should be 1."
            );
        }
        let part_data_uri = &data_uri.part_data_uris[0];
        if part_data_uri.partition_id != request.partition_id {
            return_errno!(AuthStatus::InternalErr,
                "partition_id mismatching, request.partition_id: {}, part_data_uri.partition_id: {}.",
                request.partition_id, part_data_uri.partition_id);
        }

        // TODO: Verify the requester's permissions

        let decrypter: Box<dyn Decrypter> = match self.scheme {
            AsymmetricScheme::RSA => Box::new(RsaPrivateKeyHolder::private_key_from_pem_pkcs1(
                &self.kek_pri,
            )?),
            AsymmetricScheme::SM2 => Box::new(Sm2Decrypter::private_key_from_pem(&self.kek_pri)?),
        };

        let public_key = match request.public_key {
            Some(pk) => pk,
            None => return_errno!(AuthStatus::InternalErr, "public key is empty."),
        };

        let encrypter: Box<dyn Encrypter> = match AsymmetricScheme::from_str(&public_key.scheme)? {
            AsymmetricScheme::RSA => Box::new(RsaPublicKeyHolder::public_key_from_pem(
                &public_key.public_key,
            )?),
            AsymmetricScheme::SM2 => {
                Box::new(Sm2Encrypter::public_key_from_pem(&public_key.public_key)?)
            }
        };

        let mut data_keys: Vec<SegmentDataMeta> = vec![];
        // for each segment key
        for seg_data_uri in part_data_uri.seg_data_uris.iter() {
            let opt_seg = seg_data_uri
                .optional_seg
                .clone()
                .ok_or(errno!(AuthStatus::InternalErr, "data key is empty."))?;

            let seg_key = match opt_seg {
                OptionalSeg::SegmentDataMeta(seg) => seg,
                _ => return_errno!(AuthStatus::InternalErr, "error seg type."),
            };
            if seg_key.secret_shard_id == self.secret_shard_id {
                // decrypt data key using private key of authmanager
                let data_key = decrypter.decrypt(&seg_key.encrypted_data_key)?;
                // encrypt data key using public key of institution
                let encrypted_data_key = encrypter.encrypt(&data_key)?;

                let rencrypted_seg_key = SegmentDataMeta {
                    segment_id: seg_key.segment_id,
                    secret_shard_id: seg_key.secret_shard_id,
                    encrypted_data_key: encrypted_data_key,
                    // only need to re-encrypt data key.
                    // mac and signature doesn't need to be filled
                    mac: Vec::new(),
                    signature: Vec::new(),
                };
                data_keys.push(rencrypted_seg_key);
            }
        }
        Ok(data_keys)
    }
}
