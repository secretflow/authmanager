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

use super::storage_wrapper::StorageWrapper;
use crate::utils::crypto::{
    rsa::RsaPublicKeyHolder, scheme::AsymmetricScheme, sm2::Sm2Verifier, verifier::Verifier,
};
use async_trait::async_trait;
use auth_manager_tonic::sdc::{dataagent::*, PublicKey, *};
use auth_types::*;
use log::warn;
use prost::Message;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

// inmemory storage implementation
#[derive(Debug)]
pub struct MemoryClient {
    data_auth_map: Arc<Mutex<HashMap<String, Vec<DataAuth>>>>,
    data_meta_map: Arc<Mutex<HashMap<String, DataMeta>>>,
    public_key_map: Arc<Mutex<HashMap<String, PublicKey>>>,
    // mac key is encrypted by public_key of authmanager
    mac_key_map: Arc<Mutex<HashMap<String, (String, String)>>>,
}

#[async_trait]
impl StorageWrapper for MemoryClient {
    // put
    async fn create_data_with_auth(
        &self,
        request: CreateDataWithAuthRequest,
    ) -> AuthResult<CreateDataWithAuthResponse> {
        let data_meta = &request
            .data_info
            .ok_or(errno!(AuthStatus::OptionNoneErr, "data meta is empty."))?;
        let data_auth = &request
            .data_auth
            .ok_or(errno!(AuthStatus::OptionNoneErr, "data auth is empty."))?;
        // verify signature when it's used, so not verify when it's stored
        // store data_meta、data_auth
        let mut data_meta_map = self.data_meta_map.lock().unwrap();
        let mut data_auth_map = self.data_auth_map.lock().unwrap();
        if data_meta_map.contains_key(&data_meta.data_uuid) {
            return_errno!(
                AuthStatus::AlreadyExists,
                "data_uuid {} meta has already stored.",
                &data_meta.data_uuid
            );
        }
        data_meta_map.insert(data_meta.data_uuid.clone(), data_meta.clone());

        (*data_auth_map
            .entry(data_meta.data_uuid.clone())
            .or_insert(vec![]))
        .push(data_auth.clone());
        Ok(CreateDataWithAuthResponse {
            status: Some(auth_manager_tonic::Status {
                code: auth_manager_tonic::Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            data_access_token: None,
            data_uri: None,
        })
    }

    async fn register_ins_pub_key(
        &self,
        request: RegisterInsPubKeyRequest,
    ) -> AuthResult<RegisterInsPubKeyResponse> {
        let public_key = request.public_key.ok_or(errno!(
            AuthStatus::OptionNoneErr,
            "ins_id: {} does not have public key.",
            &request.ins_id
        ))?;
        // 1. verify signature(use public key of institution)
        let verifier: Box<dyn Verifier> = match AsymmetricScheme::from_str(&public_key.scheme)? {
            AsymmetricScheme::RSA => Box::new(RsaPublicKeyHolder::public_key_from_pem(
                &public_key.public_key,
            )?),
            AsymmetricScheme::SM2 => {
                Box::new(Sm2Verifier::public_key_from_pem(&public_key.public_key)?)
            }
        };
        let data = [request.ins_id.as_bytes(), &public_key.encode_to_vec()].concat();
        if !verifier.verifier(&data, &request.signature)? {
            warn!(
                "RegisterInsPubKeyRequest: signature verify failed, ins_id: {}",
                &request.ins_id
            );
        }
        // 2. store public key
        let mut public_key_map = self.public_key_map.lock().unwrap();
        if public_key_map.contains_key(&request.ins_id) {
            return_errno!(
                AuthStatus::AlreadyExists,
                "ins_id {} has already register public key.",
                &request.ins_id
            );
        }
        public_key_map.insert(request.ins_id.clone(), public_key.clone());
        Ok(RegisterInsPubKeyResponse {
            status: Some(auth_manager_tonic::Status {
                code: auth_manager_tonic::Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
        })
    }

    async fn create_data_mac_key(
        &self,
        request: CreateDataMacKeyRequest,
    ) -> AuthResult<CreateDataMacKeyResponse> {
        let mut mac_key_map = self.mac_key_map.lock().unwrap();
        if mac_key_map.contains_key(&request.data_uuid) {
            return_errno!(
                AuthStatus::AlreadyExists,
                "data_uuid {} mac key has already stored.",
                &request.data_uuid
            )
        }
        mac_key_map.insert(
            request.data_uuid.clone(),
            (
                request.encrypted_mac_key.clone(),
                request.encryption_algorithm.clone(),
            ),
        );
        Ok(CreateDataMacKeyResponse {
            status: Some(auth_manager_tonic::Status {
                code: auth_manager_tonic::Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
        })
    }

    // get
    async fn get_data_mac_key(
        &self,
        request: GetDataMacKeyRequest,
    ) -> AuthResult<GetDataMacKeyResponse> {
        let mac_key_map = self.mac_key_map.lock().unwrap();
        let encrypted_mac_key = mac_key_map.get(&request.data_uuid).ok_or(errno!(
            AuthStatus::OptionNoneErr,
            "data_uuid: {} does not have mac key.",
            &request.data_uuid
        ))?;
        Ok(GetDataMacKeyResponse {
            status: Some(auth_manager_tonic::Status {
                code: auth_manager_tonic::Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            encryption_algorithm: encrypted_mac_key.1.clone(),
            encrypted_mac_key: encrypted_mac_key.0.clone(),
        })
    }

    async fn get_data_meta(&self, request: GetDataMetaRequest) -> AuthResult<GetDataMetaResponse> {
        let mut data_metas: Vec<DataMeta> = vec![];
        let data_meta_map = self.data_meta_map.lock().unwrap();
        for data_uuid in request.data_uuid.iter() {
            data_metas.push(
                data_meta_map
                    .get(data_uuid)
                    .ok_or(errno!(
                        AuthStatus::OptionNoneErr,
                        "input: {} does not have data meta.",
                        data_uuid
                    ))?
                    .clone(),
            );
        }
        Ok(GetDataMetaResponse {
            status: Some(auth_manager_tonic::Status {
                code: auth_manager_tonic::Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            data_meta: data_metas,
        })
    }

    async fn get_data_auth(&self, request: GetDataAuthRequest) -> AuthResult<GetDataAuthResponse> {
        let mut data_auths: Vec<DataAuth> = vec![];
        let data_auth_map = self.data_auth_map.lock().unwrap();
        for data_uuid in request.data_uuid.iter() {
            data_auths.append(
                &mut data_auth_map
                    .get(data_uuid)
                    .ok_or(errno!(
                        AuthStatus::OptionNoneErr,
                        "input: {} does not have data auth.",
                        data_uuid
                    ))?
                    .clone(),
            );
        }
        Ok(GetDataAuthResponse {
            status: Some(auth_manager_tonic::Status {
                code: auth_manager_tonic::Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            data_auth: data_auths,
        })
    }

    async fn get_ins_public_key(
        &self,
        request: GetInsPubKeyRequest,
    ) -> AuthResult<GetInsPubKeyResponse> {
        let public_key_map = self.public_key_map.lock().unwrap();
        let public_key: PublicKey = public_key_map
            .get(&request.ins_id)
            .ok_or(errno!(
                AuthStatus::OptionNoneErr,
                "ins_id: {} does not have public key.",
                &request.ins_id
            ))?
            .clone();
        Ok(GetInsPubKeyResponse {
            status: Some(auth_manager_tonic::Status {
                code: auth_manager_tonic::Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            public_key: Some(public_key),
        })
    }

    async fn get_partition_access_info(
        &self,
        request: GetPartitionAccessInfoRequest,
    ) -> AuthResult<GetDataAccessInfoResponse> {
        // collect data_uuid -> partition_ids map
        let mut partition_map: HashMap<String, Vec<String>> = HashMap::new();
        for partition_id_info in request.partition_id_infos.iter() {
            partition_map
                .entry(partition_id_info.data_uuid.clone())
                .or_insert(vec![])
                .push(partition_id_info.partition_id.clone());
        }

        // collect data info
        let mut data_uris: Vec<DataUri> = vec![];
        let data_meta_map = self.data_meta_map.lock().unwrap();
        for (data_uuid, partition_ids) in &partition_map {
            // for every data_uuid
            let data_meta: &DataMeta = data_meta_map.get(data_uuid).ok_or(errno!(
                AuthStatus::OptionNoneErr,
                "data_uuid: {} does not have meta data.",
                data_uuid
            ))?;

            // for every partition_id
            let mut part_data_uris: Vec<PartitionDataUri> = vec![];
            for partition_id in partition_ids.iter() {
                let partition_meta_data: Vec<&PartitionDataMeta> = data_meta
                    .partition_data
                    .iter()
                    .filter(|s| s.partition_id == *partition_id)
                    .collect();

                if partition_meta_data.len() != 1 {
                    return_errno!(
                        AuthStatus::InternalErr,
                        "partition meta data num is {}",
                        partition_meta_data.len()
                    )
                }

                let mut seg_data_uris = vec![];
                for segment_meta_data in partition_meta_data[0].segment_data.iter() {
                    // generate segment data uri
                    let segment_data_uri = SegmentDataUri {
                        segment_id: 0,
                        secret_shard_id: 0,
                        mac: "default".as_bytes().to_vec(), // useless
                        status: "UPLOAD".to_owned(),        // useless
                        data_uri: "default".to_owned(),     // useless
                        optional_seg: Some(segment_data_uri::OptionalSeg::SegmentDataMeta(
                            segment_meta_data.clone(),
                        )),
                    };
                    seg_data_uris.push(segment_data_uri);
                }
                // generate partion data uri
                let partition_data_uri = PartitionDataUri {
                    partition_id: "default".to_owned(),
                    seg_data_uris,
                };
                part_data_uris.push(partition_data_uri);
            }
            // generate data uri(binding to data_uuid)
            let data_uri = DataUri {
                data_uuid: data_uuid.clone(),
                part_data_uris,
            };

            data_uris.push(data_uri);
        }

        Ok(GetDataAccessInfoResponse {
            status: Some(auth_manager_tonic::Status {
                code: auth_manager_tonic::Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            data_access_token: None,
            data_uri_with_dk: data_uris,
        })
    }

    async fn get_access_info(
        &self,
        _request: GetDataAccessInfoRequest,
    ) -> AuthResult<GetDataAccessInfoResponse> {
        Ok(GetDataAccessInfoResponse {
            status: Some(auth_manager_tonic::Status {
                code: auth_manager_tonic::Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            data_access_token: None,
            data_uri_with_dk: vec![],
        })
    }
}

impl MemoryClient {
    pub fn new() -> Self {
        let data_auth_map = Arc::new(Mutex::new(HashMap::new()));
        let data_meta_map = Arc::new(Mutex::new(HashMap::new()));
        let public_key_map = Arc::new(Mutex::new(HashMap::new()));
        let mac_key_map = Arc::new(Mutex::new(HashMap::new()));
        Self {
            data_auth_map,
            data_meta_map,
            public_key_map,
            mac_key_map,
        }
    }
}
