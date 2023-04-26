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

pub(crate) mod constant;
mod create_data_mac_key_impl;
mod create_data_with_auth_impl;
mod get_compute_meta_impl;
mod get_export_data_key_impl;
mod get_ra_cert_pems_impl;
mod register_ins_pub_key_impl;

use super::storage::memory_client::*;
use super::storage::storage_wrapper::StorageWrapper;

use super::storage::remote_storage_client::RemoteStorageClient;
use super::utils::crypto::scheme::AsymmetricScheme;
use auth_manager_tonic::sdc::authmanager::auth_manager_server::AuthManager;
use auth_manager_tonic::sdc::authmanager::*;
use auth_manager_tonic::sdc::dataagent::*;
use auth_types::*;
use constant::*;
use log::info;
use openssl::rsa::Rsa;
use reqwest_middleware::ClientBuilder;
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::RetryTransientMiddleware;
use std::str::from_utf8;
use tonic::{Request, Response};

#[derive(Debug)]
#[allow(unused)]
pub struct AuthManagerImpl {
    storage_client: Box<dyn StorageWrapper>,
    // public-private key algorithm: SM2/RSA
    scheme: AsymmetricScheme,
    // private key
    kek_pub: String,
    // public key
    kek_pri: String,
    // secret shared id: not used yet
    secret_shard_id: i32,
    // run mode for authmanager
    // Production Mode: need RA
    // Simulation Mode: doesn't need RA
    mode: String,
    // data storage
    // remote: be used in condition that has dedicated storage service, http access
    // inmemory: be used default that all data in memory of authmanager
    storage_backend: String,
    // where public-private key is from
    // standalone: default, self-generated
    // cluster: aecs generated(aecs is a service has not yet open source)
    secret_key_from: String,
}

impl AuthManagerImpl {
    pub fn new(
        remote_storage_endpoint: &str,
        secret_shard_id: i32,
        scheme: AsymmetricScheme,
        mode: &str,
        storage_backend: &str,
        secret_key_from: &str,
    ) -> Self {
        // get public-private key pair
        let (public_key, private_key) = match secret_key_from {
            "standalone" => {
                let rsa = Rsa::generate(RSA_BIT_LEN).expect("create rsa key pair failed");
                let pubkey_pem = rsa
                    .public_key_to_pem_pkcs1()
                    .expect("create pem public key failed");
                let prikey_pem = rsa
                    .private_key_to_pem()
                    .expect("create pem private key failed");
                let public_key = from_utf8(&pubkey_pem).unwrap();
                let private_key = from_utf8(&prikey_pem).unwrap();
                (public_key.to_string(), private_key.to_string())
            }
            _ => panic!("mode wrong"),
        };
        // get backend storage client
        let storage_client: Box<dyn StorageWrapper> = match storage_backend {
            "remote" => {
                let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);

                let http_client = ClientBuilder::new(reqwest::Client::new())
                    .with(RetryTransientMiddleware::new_with_policy(retry_policy))
                    .build();
                Box::new(RemoteStorageClient::new(
                    "http",
                    remote_storage_endpoint,
                    http_client,
                ))
            }
            "inmemory" => Box::new(MemoryClient::new()),
            _ => panic!("storage_backend wrong"),
        };

        Self {
            storage_client: storage_client,
            kek_pub: public_key,
            kek_pri: private_key,
            secret_shard_id,
            scheme,
            mode: mode.to_owned(),
            storage_backend: storage_backend.to_owned(),
            secret_key_from: secret_key_from.to_owned(),
        }
    }
}

// interface implementation for GRPC service
#[tonic::async_trait]
impl AuthManager for AuthManagerImpl {
    // not used yet, will be used in the near future
    async fn get_export_data_key(
        &self,
        request: Request<GetExportDataKeyRequest>,
    ) -> Result<Response<GetExportDataKeyResponse>, tonic::Status> {
        let ip = request.remote_addr();
        let request_body = request.into_inner();

        let reply = match self.get_export_data_key_impl(request_body.clone()).await {
            Ok(data_keys) => {
                info!(target: "monitor_log", "|get_export_data_key|{:?}|{}|{}|", ip, 0, "success");
                GetExportDataKeyResponse {
                    status: Some(auth_manager_tonic::Status {
                        code: auth_manager_tonic::Code::Ok as i32,
                        message: "success".to_owned(),
                        details: vec![],
                    }),

                    data_keys,
                }
            }
            Err(e) => {
                info!(target: "monitor_log", "|get_export_data_key|{:?}|{}|{}|", ip, e.errno(), e.to_string());
                GetExportDataKeyResponse {
                    status: Some(auth_manager_tonic::Status {
                        code: map_authstatus_to_i32(e.errno()),
                        message: e.to_string(),
                        details: vec![],
                    }),
                    data_keys: Vec::new(),
                }
            }
        };
        Ok(Response::new(reply))
    }

    async fn get_compute_meta(
        &self,
        request: tonic::Request<GetComputeMetaRequest>,
    ) -> Result<tonic::Response<GetComputeMetaResponse>, tonic::Status> {
        let ip = request.remote_addr();
        let request_body = request.into_inner();

        let reply = match self.get_compute_meta_impl(request_body.clone()).await {
            Ok(compute_meta) => {
                info!(target: "monitor_log", "|get_compute_meta|{:?}|{}|{}|", ip, 0, "success");
                GetComputeMetaResponse {
                    status: Some(auth_manager_tonic::Status {
                        code: auth_manager_tonic::Code::Ok as i32,
                        message: "success".to_owned(),
                        details: vec![],
                    }),
                    encrypted_response: Some(compute_meta),
                }
            }
            Err(e) => {
                info!(target: "monitor_log", "|get_compute_meta|{:?}|{}|{}|", ip, e.errno(), e.to_string());
                GetComputeMetaResponse {
                    status: Some(auth_manager_tonic::Status {
                        code: map_authstatus_to_i32(e.errno()),
                        message: e.to_string(),
                        details: vec![],
                    }),
                    encrypted_response: None,
                }
            }
        };
        Ok(Response::new(reply))
    }

    async fn get_ra_cert_pems(
        &self,
        request: tonic::Request<GetRaCertPemsRequest>,
    ) -> Result<tonic::Response<GetRaCertPemsResponse>, tonic::Status> {
        let ip = request.remote_addr();
        let request_body = request.into_inner();

        let reply = match self.get_ra_cert_pems_impl(request_body.clone()).await {
            Ok(report_with_certs) => {
                info!(target: "monitor_log", "|get_ra_cert_pems|{:?}|{}|{}|", ip, 0, "success");
                GetRaCertPemsResponse {
                    status: Some(auth_manager_tonic::Status {
                        code: auth_manager_tonic::Code::Ok as i32,
                        message: "success".to_owned(),
                        details: vec![],
                    }),
                    report_with_certs,
                }
            }
            Err(e) => {
                info!(target: "monitor_log", "|get_ra_cert_pems|{:?}|{}|{}|", ip, e.errno(), e.to_string());
                GetRaCertPemsResponse {
                    status: Some(auth_manager_tonic::Status {
                        code: map_authstatus_to_i32(e.errno()),
                        message: e.to_string(),
                        details: vec![],
                    }),
                    report_with_certs: vec![],
                }
            }
        };
        Ok(Response::new(reply))
    }

    async fn create_data_with_auth(
        &self,
        request: tonic::Request<CreateDataWithAuthRequest>,
    ) -> Result<tonic::Response<CreateDataWithAuthResponse>, tonic::Status> {
        let ip = request.remote_addr();
        let request_body = request.into_inner();
        let reply = match self.create_data_with_auth_impl(request_body.clone()).await {
            Ok(resp) => {
                info!(target: "monitor_log", "|create_data_with_auth|{:?}|{}|{}|", ip, 0, "success");
                resp
            }
            Err(e) => {
                info!(target: "monitor_log", "|create_data_with_auth|{:?}|{}|{}|", ip, e.errno(), e.to_string());
                CreateDataWithAuthResponse {
                    status: Some(auth_manager_tonic::Status {
                        code: map_authstatus_to_i32(e.errno()),
                        message: e.to_string(),
                        details: vec![],
                    }),
                    data_access_token: None,
                    data_uri: None,
                }
            }
        };

        Ok(Response::new(reply))
    }

    async fn register_ins_pub_key(
        &self,
        request: tonic::Request<RegisterInsPubKeyRequest>,
    ) -> Result<tonic::Response<RegisterInsPubKeyResponse>, tonic::Status> {
        let ip = request.remote_addr();
        let request_body = request.into_inner();
        let reply = match self.register_ins_pub_key_impl(request_body.clone()).await {
            Ok(resp) => {
                info!(target: "monitor_log", "|register_ins_pub_key|{:?}|{}|{}|", ip, 0, "success");
                resp
            }
            Err(e) => {
                info!(target: "monitor_log", "|register_ins_pub_key|{:?}|{}|{}|", ip, e.errno(), e.to_string());
                RegisterInsPubKeyResponse {
                    status: Some(auth_manager_tonic::Status {
                        code: map_authstatus_to_i32(e.errno()),
                        message: e.to_string(),
                        details: vec![],
                    }),
                }
            }
        };
        Ok(Response::new(reply))
    }

    async fn create_data_mac_key(
        &self,
        request: tonic::Request<CreateDataMacKeyRequest>,
    ) -> Result<tonic::Response<CreateDataMacKeyResponse>, tonic::Status> {
        let ip = request.remote_addr();
        let request_body = request.into_inner();
        let reply = match self.create_data_mac_key_impl(request_body.clone()).await {
            Ok(resp) => {
                info!(target: "monitor_log", "|create_data_mac_key|{:?}|{}|{}|", ip, 0, "success");
                resp
            }
            Err(e) => {
                info!(target: "monitor_log", "|create_data_mac_key|{:?}|{}|{}|", ip, e.errno(), e.to_string());
                CreateDataMacKeyResponse {
                    status: Some(auth_manager_tonic::Status {
                        code: map_authstatus_to_i32(e.errno()),
                        message: e.to_string(),
                        details: vec![],
                    }),
                }
            }
        };
        Ok(Response::new(reply))
    }
}
