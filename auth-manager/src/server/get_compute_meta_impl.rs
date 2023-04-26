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

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    vec,
};

use log::{info, warn};

use std::iter::zip;

use crate::utils::crypto::{
    decrypter::Decrypter,
    encrypter::Encrypter,
    hmac::*,
    rsa::{RsaPrivateKeyHolder, RsaPublicKeyHolder},
    scheme::*,
    sm2::{Sm2Decrypter, Sm2Encrypter, Sm2Verifier},
    verifier::Verifier,
};
use crate::{unified_attestation_wrapper::*, utils::crypto::sha::sha256};
use auth_manager_tonic::sdc::{
    authmanager::{self, compute_meta, ComputeMeta, GetComputeMetaRequest},
    dataagent::*,
    teeapps::TeeTaskParams,
    AsymmetricSecret, PublicKey, *,
};
use auth_types::*;
use hex::encode_upper;
use prost::Message;

use super::{constant::*, AuthManagerImpl};

fn get_schema(data_uuid: &str, data_metas: &[DataMeta]) -> AuthResult<Option<Schema>> {
    for data_meta in data_metas.iter() {
        if data_uuid == data_meta.data_uuid {
            if data_meta.optional_schema.is_none() {
                if data_meta.data_format == "CSV" {
                    return_errno!(
                        AuthStatus::InternalErr,
                        "data uuid :{}, schema is empty!",
                        data_uuid
                    )
                }
                return Ok(None);
            }
            let opt_schema = data_meta.optional_schema.clone().ok_or(errno!(
                AuthStatus::OptionNoneErr,
                "optional_schema is empty."
            ))?;
            let data_meta::OptionalSchema::Schema(schema) = opt_schema;
            return Ok(Some(schema));
        }
    }
    return_errno!(
        AuthStatus::InternalErr,
        "data uuid {} is not exist.",
        data_uuid
    )
}

fn verify_data_auth_sig(verifier: &Box<dyn Verifier>, data_auth: &DataAuth) -> AuthResult<bool> {
    // signature = SIG(data_uuid||allowed_ins_ids||allowed_apps||operators||extra_limits||optional_schema)
    let allowed_apps: Vec<u8> = data_auth
        .allowed_apps
        .iter()
        .flat_map(|x| x.encode_to_vec())
        .collect();

    let schema = match &data_auth.optional_schema {
        Some(ref opt_schema) => {
            let &data_auth::OptionalSchema::Schema(ref s) = opt_schema;
            s.encode_to_vec()
        }
        None => vec![],
    };

    let data = [
        data_auth.data_uuid.as_bytes(),
        data_auth.allowed_ins_ids.concat().as_bytes(),
        &allowed_apps,
        data_auth.operators.concat().as_bytes(),
        data_auth.extra_limits.as_bytes(),
        &schema,
    ]
    .concat();

    return Ok(verifier.verifier(&data, &data_auth.signature)?);
}

impl AuthManagerImpl {
    fn verify_data_meta_mac(
        &self,
        data_meta: &DataMeta,
        resp: &GetDataMacKeyResponse,
    ) -> AuthResult<()> {
        let decrypter: Box<dyn Decrypter> = match self.scheme {
            // use private key from authmanager
            // RSA: pkcs1 pkcs1  SM2: x509 pkcs8
            // TODO Subsequent unification of rsa and sm2 key generation standards
            AsymmetricScheme::RSA => Box::new(RsaPrivateKeyHolder::private_key_from_pem_pkcs1(
                &self.kek_pri,
            )?),
            AsymmetricScheme::SM2 => Box::new(Sm2Decrypter::private_key_from_pem(&self.kek_pri)?),
        };
        let mac_key = decrypter.decrypt(resp.encrypted_mac_key.as_bytes())?;
        let ancestors: Vec<u8> = data_meta
            .ancestors
            .iter()
            .flat_map(|x| x.encode_to_vec())
            .collect();
        let all_ancestors: Vec<u8> = data_meta
            .all_ancestors
            .iter()
            .flat_map(|x| x.encode_to_vec())
            .collect();
        let data = [
            data_meta.data_uuid.as_bytes(),
            data_meta.source_type.as_bytes(),
            &ancestors,
            &all_ancestors,
        ]
        .join(SEPARATOR.as_bytes());
        let hmac = generate_hmac(
            HmacScheme::from_str(resp.encryption_algorithm.as_str())?,
            &mac_key,
            &data,
        )?;
        let calc_mac = String::from_utf8(hmac)
            .map_err(|e| errno!(AuthStatus::InternalErr, "vec u8 to string err: {:?}", e))?;
        if calc_mac != data_meta.mac {
            return_errno!(
                AuthStatus::CryptoErr,
                "calc_mac {} != data_meta_mac {}",
                &calc_mac,
                &data_meta.mac
            )
        }

        Ok(())
    }

    // Verify the validity of SegmentDataMeta::signature, which is used to prevent the risk of data owner being tampered with:
    // Because the signature contains the plaintext information of the data key, only the real data uploader can sign correctly
    fn verify_seg_data_meta_sig(
        &self,
        data_meta: &DataMeta,
        part_data_meta: &PartitionDataMeta,
        seg_data_meta: &SegmentDataMeta,
        public_key: &PublicKey,
    ) -> AuthResult<()> {
        let decrypter: Box<dyn Decrypter> = match self.scheme {
            // use private key from authmanager
            // RSA: pkcs1 pkcs1  SM2: x509 pkcs8
            // TODO Subsequent unification of rsa and sm2 key generation standards
            AsymmetricScheme::RSA => Box::new(RsaPrivateKeyHolder::private_key_from_pem_pkcs1(
                &self.kek_pri,
            )?),
            AsymmetricScheme::SM2 => Box::new(Sm2Decrypter::private_key_from_pem(&self.kek_pri)?),
        };
        // use public key from institution
        // RSA: x509 pkcs8  SM2: x509 pkcs8
        // TODO Subsequent unification of rsa and sm2 key generation standards
        let verifier: Box<dyn Verifier> = match AsymmetricScheme::from_str(&public_key.scheme)? {
            AsymmetricScheme::RSA => Box::new(RsaPublicKeyHolder::public_key_from_pem(
                &public_key.public_key,
            )?),
            AsymmetricScheme::SM2 => {
                Box::new(Sm2Verifier::public_key_from_pem(&public_key.public_key)?)
            }
        };
        // SIG(data_uuid || partition_id  || segment_id || secret_shard_id || data key)
        let data_key = decrypter.decrypt(&seg_data_meta.encrypted_data_key)?;
        let data = [
            data_meta.data_uuid.as_bytes(),
            part_data_meta.partition_id.as_bytes(),
            &seg_data_meta.segment_id.to_le_bytes(), // NOTICE: little endian
            &seg_data_meta.secret_shard_id.to_le_bytes(), // NOTICE: little endian
            &data_key,
        ]
        .concat();

        if !verifier.verifier(&data, &seg_data_meta.signature)? {
            return Err(errno!(
                AuthStatus::CryptoErr,
                "verify data_uuid {} partition_id {} segment_id {} signature failed",
                &data_meta.data_uuid,
                &part_data_meta.partition_id,
                seg_data_meta.segment_id
            ));
        }
        Ok(())
    }

    fn verify_data_meta_sig(&self, data_meta: &DataMeta, public_key: &PublicKey) -> AuthResult<()> {
        for part_data_meta in data_meta.partition_data.iter() {
            for seg_data_meta in part_data_meta.segment_data.iter() {
                self.verify_seg_data_meta_sig(
                    data_meta,
                    part_data_meta,
                    seg_data_meta,
                    public_key,
                )?;
            }
        }
        Ok(())
    }

    async fn get_data_metas(&self, data_uuids: Vec<&str>) -> AuthResult<Vec<DataMeta>> {
        for &data_uuid in data_uuids.iter() {
            auth_assert!(!data_uuid.is_empty(), "data uuid is empty");
        }
        let request = GetDataMetaRequest {
            header: Some(auth_manager_tonic::RequestHeader::default()),
            data_uuid: data_uuids.iter().map(|&s| String::from(s)).collect(),
        };
        let response = self.storage_client.get_data_meta(request).await?;
        // make sure the response is consist with the request
        auth_assert_eq!(response.data_meta.len(), data_uuids.len());
        for (x, y) in zip(data_uuids, &response.data_meta) {
            auth_assert_eq!(x, y.data_uuid);
        }

        for data_meta in response.data_meta.iter() {
            // get institution public_key
            let public_key = self.get_ins_public_key(&data_meta.owner_id).await?;
            // if data's source type is TEE which means it's intermediate data calculated
            // by TEE，we need to verify mac to prevent blood relationship from being tampered
            if SourceType::from_str(&data_meta.source_type)? == SourceType::Tee {
                let mac_key_resp = self
                    .storage_client
                    .get_data_mac_key(GetDataMacKeyRequest {
                        header: Some(auth_manager_tonic::RequestHeader::default()),
                        data_uuid: data_meta.data_uuid.clone(),
                    })
                    .await?;
                self.verify_data_meta_mac(data_meta, &mac_key_resp)?;
            } else {
                // prevent data from being tampered
                self.verify_data_meta_sig(data_meta, &public_key)?;
            }
        }
        return Ok(response.data_meta);
    }

    // request data auth infos
    //
    // @param data_uuids: data uuid list
    // @param grantee: institution id being authorized
    //
    // @return HashMap(data_uuid -> data_auths), the institution ids being authoried
    // in DataAuth record contains `grantee`
    async fn get_data_auths(
        &self,
        data_metas: &Vec<DataMeta>,
        grantee: &String,
    ) -> AuthResult<HashMap<String, Vec<DataAuth>>> {
        let data_uuids: Vec<String> = data_metas.iter().map(|x| x.data_uuid.clone()).collect();
        for data_uuid in data_uuids.iter() {
            auth_assert!(!data_uuid.is_empty(), "data uuid is empty");
        }
        let request = GetDataAuthRequest {
            header: Some(auth_manager_tonic::RequestHeader::default()),
            data_uuid: data_uuids.clone(),
        };
        let response = self.storage_client.get_data_auth(request).await?;
        // make sure the response is consist with the request
        auth_assert!(
            response.data_auth.len() >= data_uuids.len(),
            "response.data_auth.len {} should large than data_uuids.len {}",
            response.data_auth.len(),
            data_uuids.len()
        );
        // data_uuid -> DataAuth list
        // One piece of data may have multiple pieces of authorization information
        let mut data_auth_map: HashMap<String, Vec<DataAuth>> = HashMap::new();
        // init data_auth_map
        for input in data_uuids.iter() {
            data_auth_map.insert(input.into(), vec![]);
        }
        for data_auth in response.data_auth.iter() {
            auth_assert_true!(data_auth_map.contains_key(&data_auth.data_uuid));
            // use unwrap directly, since we assert `data_auth_map` contains the key before
            let vec = data_auth_map.get_mut(&data_auth.data_uuid).unwrap();
            // only the authorization information authorized to the grantee is retained
            if data_auth.allowed_ins_ids.contains(grantee)
                || data_auth.allowed_ins_ids.contains(&ALLOWED_ALL.to_string())
            {
                vec.push(data_auth.clone());
            }
        }
        self.verify_data_auths(data_metas, &mut data_auth_map)
            .await?;
        Ok(data_auth_map)
    }

    async fn get_ins_public_key(&self, ins_id: &str) -> AuthResult<PublicKey> {
        let request = GetInsPubKeyRequest {
            header: Some(auth_manager_tonic::RequestHeader::default()),
            ins_id: ins_id.to_string(),
        };
        let response = self.storage_client.get_ins_public_key(request).await?;
        let public_key = response
            .public_key
            .ok_or(errno!(AuthStatus::OptionNoneErr, "data key is empty."))?;
        Ok(public_key)
    }

    // Verify that each data has at least one piece of authorization information signed by the data owner
    // @return HashMap(data_uuid -> data_auths), invalid data auths will be filtered
    async fn verify_data_auths<'a>(
        &self,
        data_metas: &Vec<DataMeta>,
        data_auths: &'a mut HashMap<String, Vec<DataAuth>>,
    ) -> AuthResult<()> {
        for data_meta in data_metas {
            let public_key = self.get_ins_public_key(&data_meta.owner_id).await?;
            // use public key from institution
            // RSA: x509 pkcs8  SM2: x509 pkcs8
            // TODO Subsequent unification of rsa and sm2 key generation standards
            let verifier: Box<dyn Verifier> = match AsymmetricScheme::from_str(&public_key.scheme)?
            {
                AsymmetricScheme::RSA => Box::new(RsaPublicKeyHolder::public_key_from_pem(
                    &public_key.public_key,
                )?),
                AsymmetricScheme::SM2 => {
                    Box::new(Sm2Verifier::public_key_from_pem(&public_key.public_key)?)
                }
            };

            let data_auth_list = data_auths.get_mut(&data_meta.data_uuid).ok_or(errno!(
                AuthStatus::PermissionDenied,
                "requester has not been authorized any right to access this data {}, since the data auth is empty.",
                data_meta.data_uuid
            ))?;

            let mut keep: Vec<bool> = vec![];
            for data_auth in data_auth_list.iter() {
                let success = verify_data_auth_sig(&verifier, data_auth)?;
                keep.push(success);
                if !success {
                    warn!(
                        "Invalid data auth: signature verify failed, data uuid: {}",
                        data_meta.data_uuid
                    );
                }
            }
            // remove illegal data auth
            let mut iter = keep.iter();
            // unwrap will not cause carsh
            data_auth_list.retain(|_| *iter.next().unwrap());

            if data_auth_list.len() < 1 {
                return_errno!(
                    AuthStatus::PermissionDenied,
                    "requester has not been authorized any right to access this data {}, since the data auth is empty.",
                    data_meta.data_uuid
                )
            }
        }

        return Ok(());
    }

    // get the meta information of original data which is uploaded by institution
    async fn get_origin_data_meta(&self, ancestors: &Vec<Ancestor>) -> AuthResult<Vec<DataMeta>> {
        let data_uuids = ancestors.iter().map(|x| x.data_uuid.as_str()).collect();
        let mut data_metas = self.get_data_metas(data_uuids).await?;
        let mut keep = Vec::with_capacity(data_metas.len());
        for (ancestor, data_meta) in zip(ancestors, &data_metas) {
            // consistency check
            auth_assert_eq!(ancestor.data_uuid, data_meta.data_uuid);
            if SourceType::from_str(&data_meta.source_type)? == SourceType::User {
                auth_assert_eq!(ancestor.owner_id, data_meta.owner_id);
                keep.push(true);
            } else {
                keep.push(false);
            }
        }
        // remove illegal data auth
        let mut iter = keep.iter();
        // unwrap will not cause carsh
        data_metas.retain(|_| *iter.next().unwrap());
        Ok(data_metas)
    }

    // get the ancestors of the task's input data
    async fn get_all_ancestors(&self, task_info: &TeeTaskParams) -> AuthResult<Vec<Ancestor>> {
        let data_uuids: Vec<&str> = task_info
            .inputs
            .iter()
            .map(|x| x.data_uuid.as_str())
            .collect();

        info!("number of task inputs: {}", data_uuids.len());
        let data_metas = self.get_data_metas(data_uuids).await?;
        // unique, if duplicated
        let mut ancestors_data_uuids_set: HashSet<&String> = HashSet::new();
        let mut ancestors = vec![];

        for data_meta in data_metas.iter() {
            if !ancestors_data_uuids_set.contains(&data_meta.data_uuid) {
                ancestors_data_uuids_set.insert(&data_meta.data_uuid);
                ancestors.push(Ancestor {
                    data_uuid: data_meta.data_uuid.clone(),
                    owner_id: data_meta.owner_id.clone(),
                });
            }
            match SourceType::from_str(&data_meta.source_type)? {
                // if the data's source_type is TEE, it means intermediate data calculated by TEE.
                // so we need to find the original user-uploaded ancestors from all ancestors
                SourceType::Tee => {
                    auth_assert_false!(data_meta.all_ancestors.is_empty());
                    for ancestor in data_meta.all_ancestors.iter() {
                        if !ancestors_data_uuids_set.contains(&ancestor.data_uuid) {
                            ancestors_data_uuids_set.insert(&ancestor.data_uuid);
                            ancestors.push(ancestor.clone());
                        }
                    }
                }
                // if the data's source_type is User, it means it's uploaded by an institution
                SourceType::User => {}
            };
        }
        Ok(ancestors)
    }

    fn validate_auth_apps(
        &self,
        attestation_report: &UnifiedAttestationReport,
        allowed_apps: &Vec<EnclaveInfo>,
        public_key: &PublicKey,
        task_info: &TeeTaskParams,
    ) -> AuthResult<()> {
        if allowed_apps.is_empty() {
            return Err(errno!(
                AuthStatus::PermissionDenied,
                "allowed_apps is empty, is unsecure"
            ));
        }
        // RA report_data = SHA256( task_info || PEM(public_key))
        let data = [&task_info.encode_to_vec(), public_key.public_key.as_bytes()]
            .join(SEPARATOR.as_bytes());
        let hex_report_data = encode_upper(sha256(&data));
        // make sure at least one validation passes
        for allowed_app in allowed_apps.iter() {
            if allowed_app.hex_mrenclave.is_empty() && allowed_app.hex_mrsigner.is_empty() {
                warn!("both hex_mrenclave and hex_mrsigner empty, is unsecure");
                continue;
            }
            // NOTICE: hex must be uppercase
            // verify mrenclave
            let mut attribute1 = UnifiedAttestationAttributes::default();
            attribute1.str_tee_platform = "SGX_DCAP".to_string();
            attribute1.hex_ta_measurement = allowed_app.hex_mrenclave.to_uppercase();
            attribute1.bool_debug_disabled = "1".to_string();
            attribute1.hex_user_data = hex_report_data.clone();

            // verify mrsigner and prod_id
            // the field prod_id corresponds to product_id in configuration file Occlum.json
            /*let mut attribute2 = UnifiedAttestationAttributes::default();
            attribute2.str_tee_platform = "SGX_DCAP".to_string();
            attribute2.hex_signer = allowed_app.hex_mrsigner.to_uppercase();
            attribute2.hex_prod_id = allowed_app.hex_prod_id.to_uppercase();
            attribute2.bool_debug_disabled = "1".to_string();
            attribute2.hex_user_data = hex_report_data.clone();*/

            let policy = UnifiedAttestationPolicy {
                pem_public_key: "".to_owned(),
                main_attributes: vec![attribute1],
                nested_policies: vec![],
            };
            let str_policy = serde_json::to_string(&policy).map_err(|e| {
                errno!(
                    AuthStatus::InternalErr,
                    "report_policy {:?} to json err: {:?}",
                    &policy,
                    e
                )
            })?;
            let str_report = serde_json::to_string(attestation_report).map_err(|e| {
                errno!(
                    AuthStatus::InternalErr,
                    "report {:?} to json err: {:?}",
                    &attestation_report,
                    e
                )
            })?;
            runified_attestation_verify_auth_report(str_report.as_str(), str_policy.as_str())?;
            return Ok(());
        }
        return Err(errno!(
            AuthStatus::PermissionDenied,
            "app: {:?} not authorized to the requester.",
            attestation_report
        ));
    }

    // {
    //   "limit_functions":
    //   [
    //         base64(sha256(serialized(func)))
    //   ]
    // }
    fn parse_extra_limits(&self, extra_limits: &str) -> AuthResult<ExtraLimits> {
        Ok(serde_json::from_str(extra_limits).map_err(|e| {
            errno!(
                AuthStatus::InternalErr,
                "json extra_limits {:?} to struct err: {:?}",
                extra_limits,
                e
            )
        })?)
    }

    fn validate_auth_detail(
        &self,
        app_type: &String,
        code: &String,
        attestation_report: Option<&UnifiedAttestationReport>,
        data_auth_list: &Vec<DataAuth>,
        public_key: &PublicKey,
        task_info: &TeeTaskParams,
    ) -> AuthResult<()> {
        // make sure at least one validation passes
        for data_auth in data_auth_list.iter() {
            // verify the mrenclave of program
            // if mode != Simulation, there must be RA report
            if self.mode != "simulation"
                && (attestation_report.is_none()
                    || self
                        .validate_auth_apps(
                            attestation_report.unwrap(),
                            &data_auth.allowed_apps,
                            public_key,
                            task_info,
                        )
                        .is_err())
            {
                continue;
            }

            // verify operator of program
            // clear empty string
            let operators: Vec<String> = data_auth
                .operators
                .clone()
                .into_iter()
                .filter(|x| !x.is_empty())
                .collect();

            info!("operators: {:?}", operators);
            // if data_auth.operators is empty, it means it allows all operators
            if !operators.is_empty() && !operators.contains(app_type) {
                continue;
            }

            // verify the function info
            info!(
                "support funcs {:?} task func{:?}",
                &data_auth.extra_limits, code
            );
            // if code is not empty, extra_limits must contain the function
            if !code.is_empty() {
                let extra_limits: ExtraLimits =
                    match self.parse_extra_limits(data_auth.extra_limits.as_str()) {
                        Err(_e) => continue,
                        Ok(v) => v,
                    };
                for limit_func in extra_limits.limit_functions.iter() {
                    if *limit_func == *code {
                        return Ok(());
                    }
                }
            } else {
                return Ok(());
            }
        }
        return Err(errno!(
            AuthStatus::PermissionDenied,
            "task type:{} not authorized to the requester.",
            app_type
        ));
    }

    //
    // Task execution permission verification (automatic derivation mode): automatic derivation of intermediate data permissions
    // Example: original data: D1, D2, D3; execution function: F1, F2, F3
    //    D1 authorizes F1, F2; D2 authorizes F1, F2; D3 authorizes F2, F3
    //         D1    D2    D3
    //          \    /      |
    //            F1        |
    //               \      |
    //                D4    |
    //                  \  /
    //                   F2
    //       F2 can be executed normally, and the access permission of D4 are determined by the intersection of the permissions of D1 and D2

    async fn task_exec_perm_validation(
        &self,
        task_info: &TeeTaskParams,
        attestation_report: Option<&UnifiedAttestationReport>,
        public_key: &PublicKey,
    ) -> AuthResult<()> {
        // step1. Get all ancestors of the task (deduplicated)
        let all_ancestors = self.get_all_ancestors(task_info).await?;
        info!("all ancestors number: {}", all_ancestors.len());
        // step2. Get the meta information of the original data
        let origin_data_metas = self.get_origin_data_meta(&all_ancestors).await?;
        info!("number of origin data meta: {}", all_ancestors.len());
        // step3. Get legal data authorization information related to original data
        // Get data information that is not held by the requester because the data holder has access to the data
        let data_metas: Vec<DataMeta> = origin_data_metas
            .iter()
            .filter(|x| x.owner_id != task_info.requester_id)
            .cloned()
            .collect();
        info!(
            "number of data waiting for verification: {}",
            data_metas.len()
        );

        // Verify that the institution performing the task is authorized
        // Get legal data authorization information authorized to the task initiator institution (signature has been verified)
        // Note：At present, there is only one piece of data authorization information for one piece of data in the back-end storage,
        // but considering that users may initiate different authorizations for different institutions, it is saved in a map here
        let data_auths = self
            .get_data_auths(&data_metas, &task_info.requester_id)
            .await?;

        // Verify the authorization content (whether operator and code performing the task is authorized)
        for data_meta in origin_data_metas.iter() {
            // If the data owner is the task initiator, skip validation
            if data_meta.owner_id == task_info.requester_id {
                continue;
            }
            // Verify that a task has permission to execute a specific task type
            let data_auth_list = data_auths.get(&data_meta.data_uuid).ok_or(errno!(
                AuthStatus::PermissionDenied,
                "task:{}, input: {} does not have data auth.",
                task_info.task_id,
                data_meta.data_uuid
            ))?;
            info!(
                "verify auth of data: {}, size: {}",
                data_meta.data_uuid,
                data_auth_list.len()
            );
            self.validate_auth_detail(
                &task_info.app_type,
                &task_info.code,
                attestation_report,
                data_auth_list,
                public_key,
                task_info,
            )?;
        }
        Ok(())
    }

    pub async fn get_compute_meta_impl(
        &self,
        request: GetComputeMetaRequest,
    ) -> AuthResult<AsymmetricSecret> {
        info!("get_compute_meta  start");
        // step 1: get report
        let task_info = request.tee_task_params.ok_or(errno!(
            AuthStatus::OptionNoneErr,
            "tee_task_params is empty."
        ))?;

        // step2: get public key
        let public_key = match request.public_key {
            Some(pk) => pk,
            None => return_errno!(AuthStatus::OptionNoneErr, "public key is empty."),
        };

        // step 3: verify task permissions
        self.task_exec_perm_validation(
            &task_info,
            request.attestation_report.as_ref(),
            &public_key,
        )
        .await?;

        // step4: request task's input data keys
        let mut partition_id_infos = vec![];
        let mut inputs_set = HashSet::new();
        let mut inputs_data_uuid_set = HashSet::new();

        for input in task_info.inputs.iter() {
            if !inputs_data_uuid_set.contains(&input.data_uuid) {
                inputs_data_uuid_set.insert(input.data_uuid.clone());
            }

            if !inputs_set.contains(&(input.data_uuid.clone() + &input.partition_id)) {
                inputs_set.insert(input.data_uuid.clone() + &input.partition_id);
                partition_id_infos.push(PartitionIdInfo {
                    data_uuid: input.data_uuid.clone(),
                    partition_id: input.partition_id.clone(),
                });
            }
        }

        let req = GetPartitionAccessInfoRequest {
            header: Some(auth_manager_tonic::RequestHeader::default()),
            partition_id_infos: partition_id_infos,
        };
        let resp: GetDataAccessInfoResponse = self
            .storage_client
            .get_partition_access_info(req.clone())
            .await?;

        let data_meta_req = GetDataMetaRequest {
            header: Some(auth_manager_tonic::RequestHeader::default()),
            data_uuid: inputs_data_uuid_set.into_iter().collect(),
        };
        info!("request data: {:?}", data_meta_req.data_uuid);
        let data_meta_resp: GetDataMetaResponse = self
            .storage_client
            .get_data_meta(data_meta_req.clone())
            .await?;

        // sanity check
        if resp.data_uri_with_dk.len() != req.partition_id_infos.len() {
            return_errno!(
                AuthStatus::InternalErr,
                "data_uri_with_dk.len {} should be equal to req.partition_id_infos.len {}.",
                resp.data_uri_with_dk.len(),
                req.partition_id_infos.len()
            );
        }

        if data_meta_resp.data_meta.len() != data_meta_req.data_uuid.len() {
            return_errno!(
                AuthStatus::InternalErr,
                "data_meta_req.data_uuid.len {} should be equal to data_meta_req.data_uuid {}.",
                data_meta_resp.data_meta.len(),
                data_meta_req.data_uuid.len()
            );
        }

        let decrypter: Box<dyn Decrypter> = match self.scheme {
            // use private key from authmanager
            // RSA: pkcs1 pkcs1  SM2: x509 pkcs8
            // TODO Subsequent unification of rsa and sm2 key generation standards
            AsymmetricScheme::RSA => Box::new(RsaPrivateKeyHolder::private_key_from_pem_pkcs1(
                &self.kek_pri,
            )?),
            AsymmetricScheme::SM2 => Box::new(Sm2Decrypter::private_key_from_pem(&self.kek_pri)?),
        };

        let encrypter: Box<dyn Encrypter> = match AsymmetricScheme::from_str(&public_key.scheme)? {
            // use public key from institution
            // RSA: pkcs8 x509  SM2: pkcs8 x509
            // TODO Subsequent unification of rsa and sm2 key generation standards
            AsymmetricScheme::RSA => Box::new(RsaPublicKeyHolder::public_key_from_pem(
                &public_key.public_key,
            )?),
            AsymmetricScheme::SM2 => {
                Box::new(Sm2Encrypter::public_key_from_pem(&public_key.public_key)?)
            }
        };

        let mut inputs_hm = HashMap::new();

        for data_uri in resp.data_uri_with_dk.iter() {
            auth_assert_eq!(data_uri.part_data_uris.len(), 1);
            let part_data_uri = &data_uri.part_data_uris[0];
            if !inputs_set.contains(&(data_uri.data_uuid.clone() + &part_data_uri.partition_id)) {
                return_errno!(
                    AuthStatus::InternalErr,
                    "the task doesn't request this data, data_uuid: {}, partition_id: {}.",
                    data_uri.data_uuid,
                    part_data_uri.partition_id
                );
            }
            if !inputs_hm.contains_key(&data_uri.data_uuid) {
                let mut data_uri_ret = DataUri::default();
                data_uri_ret.data_uuid = data_uri.data_uuid.clone();
                inputs_hm.insert(data_uri.data_uuid.clone(), data_uri_ret);
            }
            let data_uri_ret = inputs_hm.get_mut(&data_uri.data_uuid).ok_or(errno!(
                AuthStatus::OptionNoneErr,
                "inputs_hm doesn't have this key {}.",
                data_uri.data_uuid
            ))?;

            let mut part_data_uri_ret = PartitionDataUri::default();
            part_data_uri_ret.partition_id = part_data_uri.partition_id.clone();

            // for each segment key
            for seg_data_uri in part_data_uri.seg_data_uris.iter() {
                let opt_seg = seg_data_uri
                    .optional_seg
                    .clone()
                    .ok_or(errno!(AuthStatus::OptionNoneErr, "data key is empty."))?;

                let seg_key = match opt_seg {
                    segment_data_uri::OptionalSeg::SegmentDataMeta(seg) => seg,
                    _ => return_errno!(AuthStatus::InternalErr, "error seg type."),
                };
                if seg_key.secret_shard_id == self.secret_shard_id {
                    // decrypt data key
                    let data_key = decrypter.decrypt(&seg_key.encrypted_data_key)?;

                    let segment_uri_ret = SegmentDataUri {
                        segment_id: seg_key.segment_id,
                        secret_shard_id: seg_key.secret_shard_id,
                        mac: seg_key.mac.clone(),
                        status: seg_data_uri.status.clone(),
                        data_uri: seg_data_uri.data_uri.clone(),
                        optional_seg: Some(segment_data_uri::OptionalSeg::DataKey(data_key)),
                    };
                    part_data_uri_ret.seg_data_uris.push(segment_uri_ret);
                }
            }
            data_uri_ret.part_data_uris.push(part_data_uri_ret);
        }

        let mut input_metas = HashMap::new();
        for entry in inputs_hm.iter() {
            let input_meta = compute_meta::InputMeta {
                // at present, schema is None
                schema: match get_schema(entry.0, &data_meta_resp.data_meta) {
                    Ok(res) => res,
                    _ => None,
                },
                data_uri_with_dks: Some(entry.1.clone()),
            };
            input_metas.insert(entry.0.clone(), input_meta);
        }

        let compute_meta: authmanager::ComputeMeta = ComputeMeta {
            cmd: "".to_owned(),
            // at present, access_token is None
            access_token: resp.data_access_token,
            public_key: Some(auth_manager_tonic::sdc::PublicKey {
                scheme: format!("{:?}", self.scheme),
                public_key: self.kek_pub.clone(),
            }),
            input_metas: input_metas,
        };

        let digital_envelope = encrypter.seal_digital_envelope(&compute_meta.encode_to_vec())?;
        info!("get_compute_meta  end");
        Ok(digital_envelope)
    }
}
