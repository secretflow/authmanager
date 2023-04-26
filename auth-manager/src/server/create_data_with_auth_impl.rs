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

use super::AuthManagerImpl;
use auth_manager_tonic::sdc::dataagent::*;
use auth_types::*;

impl AuthManagerImpl {
    pub async fn create_data_with_auth_impl(
        &self,
        request: CreateDataWithAuthRequest,
    ) -> AuthResult<CreateDataWithAuthResponse> {
        self.storage_client.create_data_with_auth(request).await
    }
}
