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
use async_trait::async_trait;
use auth_manager_tonic::sdc::dataagent::*;
use auth_types::*;
use bytes::Bytes;
use reqwest::Url;
use reqwest_middleware::ClientBuilder;
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};

const GET_DATA_META_PATH: &str = "/api/v1/data_meta/get";
const GET_DATA_AUTH_PATH: &str = "/api/v1/data_auth/get";
const GET_ACCESS_INFO_PATH: &str = "/api/v1/data_access_info/get";
const GET_PARTITION_ACCESS_INFO_PATH: &str = "/api/v1/partition_data_access_info/get";
const GET_INS_PUBLIC_KEY_PATH: &str = "/api/v1/ins_pub_key/get";

// remote storage implementation
#[derive(Debug)]
pub struct RemoteStorageClient {
    base: Url,
    http_client: reqwest_middleware::ClientWithMiddleware,
}

impl Default for RemoteStorageClient {
    fn default() -> Self {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);

        let http_client = ClientBuilder::new(reqwest::Client::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        Self {
            base: Url::parse("localhost:8080").unwrap(),
            http_client: http_client,
        }
    }
}

#[async_trait]
impl StorageWrapper for RemoteStorageClient {
    // get
    async fn get_data_meta(&self, request: GetDataMetaRequest) -> AuthResult<GetDataMetaResponse> {
        let response: GetDataMetaResponse = self.post_data(GET_DATA_META_PATH, request).await?;

        Ok(response)
    }

    async fn get_data_auth(&self, request: GetDataAuthRequest) -> AuthResult<GetDataAuthResponse> {
        let response: GetDataAuthResponse = self.post_data(GET_DATA_AUTH_PATH, request).await?;

        Ok(response)
    }

    async fn get_access_info(
        &self,
        request: GetDataAccessInfoRequest,
    ) -> AuthResult<GetDataAccessInfoResponse> {
        let response: GetDataAccessInfoResponse =
            self.post_data(GET_ACCESS_INFO_PATH, request).await?;

        Ok(response)
    }

    async fn get_partition_access_info(
        &self,
        request: GetPartitionAccessInfoRequest,
    ) -> AuthResult<GetDataAccessInfoResponse> {
        let response: GetDataAccessInfoResponse = self
            .post_data(GET_PARTITION_ACCESS_INFO_PATH, request)
            .await?;

        Ok(response)
    }

    async fn get_ins_public_key(
        &self,
        request: GetInsPubKeyRequest,
    ) -> AuthResult<GetInsPubKeyResponse> {
        let response: GetInsPubKeyResponse =
            self.post_data(GET_INS_PUBLIC_KEY_PATH, request).await?;

        Ok(response)
    }

    async fn get_data_mac_key(
        &self,
        _request: GetDataMacKeyRequest,
    ) -> AuthResult<GetDataMacKeyResponse> {
        Ok(GetDataMacKeyResponse {
            status: Some(auth_manager_tonic::Status {
                code: auth_manager_tonic::Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            encryption_algorithm: "".to_owned(),
            encrypted_mac_key: "".to_owned(),
        })
    }

    // put
    async fn create_data_with_auth(
        &self,
        _request: CreateDataWithAuthRequest,
    ) -> AuthResult<CreateDataWithAuthResponse> {
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
        _request: RegisterInsPubKeyRequest,
    ) -> AuthResult<RegisterInsPubKeyResponse> {
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
        _request: CreateDataMacKeyRequest,
    ) -> AuthResult<CreateDataMacKeyResponse> {
        Ok(CreateDataMacKeyResponse {
            status: Some(auth_manager_tonic::Status {
                code: auth_manager_tonic::Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
        })
    }
}

impl RemoteStorageClient {
    pub fn new(
        protocol: &str,
        remote_storage_endpoint: &str,
        http_client: reqwest_middleware::ClientWithMiddleware,
    ) -> RemoteStorageClient {
        let base = Url::parse(&format!("{}://{}", protocol, remote_storage_endpoint))
            .expect("Url format error!");

        RemoteStorageClient { base, http_client }
    }

    pub async fn post_data<T: prost::Message, U: prost::Message + Default>(
        &self,
        path: &str,
        body: T,
    ) -> AuthResult<U> {
        let buf: Vec<u8> = body.encode_to_vec();
        let url: Url = match self.base.join(path) {
            Ok(url) => url,
            Err(e) => return_errno!(AuthStatus::InternalErr, "url parse error: {:?}", e),
        };

        let res: reqwest::Response = self
            .http_client
            .post(url)
            .header("Content-Type", "application/x-protobuf")
            .body(buf)
            .send()
            .await
            .map_err(|e| errno!(AuthStatus::InternalErr, "request remote data err: {:?}", e))?;

        let res_body: Bytes = res
            .bytes()
            .await
            .map_err(|e| errno!(AuthStatus::InternalErr, "pb parse error: {:?}", e))?;

        Ok(U::decode(res_body)
            .map_err(|e| errno!(AuthStatus::InternalErr, "pb decode error: {:?}", e))?)
    }
}
