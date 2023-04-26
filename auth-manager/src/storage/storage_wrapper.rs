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

use std::fmt::Debug;

use async_trait::async_trait;
use auth_manager_tonic::sdc::dataagent::*;
use auth_types::*;

#[async_trait]
pub trait StorageWrapper: Send + Sync + Debug {
    // get request
    // get data meta info
    async fn get_data_meta(&self, request: GetDataMetaRequest) -> AuthResult<GetDataMetaResponse>;
    // get data auth info
    async fn get_data_auth(&self, request: GetDataAuthRequest) -> AuthResult<GetDataAuthResponse>;
    // not used yet, will be used in the near future
    async fn get_access_info(
        &self,
        request: GetDataAccessInfoRequest,
    ) -> AuthResult<GetDataAccessInfoResponse>;
    // get data info
    async fn get_partition_access_info(
        &self,
        request: GetPartitionAccessInfoRequest,
    ) -> AuthResult<GetDataAccessInfoResponse>;
    // get public key of institution
    async fn get_ins_public_key(
        &self,
        request: GetInsPubKeyRequest,
    ) -> AuthResult<GetInsPubKeyResponse>;
    // get data mac key which is used for preventing blood relationship from being tampered
    // only for data whose source_type is TEE, not a required feature here
    async fn get_data_mac_key(
        &self,
        request: GetDataMacKeyRequest,
    ) -> AuthResult<GetDataMacKeyResponse>;

    // put request
    // save data auth and data meta at the same
    async fn create_data_with_auth(
        &self,
        request: CreateDataWithAuthRequest,
    ) -> AuthResult<CreateDataWithAuthResponse>;
    // save public key of institution
    async fn register_ins_pub_key(
        &self,
        request: RegisterInsPubKeyRequest,
    ) -> AuthResult<RegisterInsPubKeyResponse>;
    // save mac key of data only for data whose source_type is TEE, not a required feature here
    async fn create_data_mac_key(
        &self,
        request: CreateDataMacKeyRequest,
    ) -> AuthResult<CreateDataMacKeyResponse>;
}
