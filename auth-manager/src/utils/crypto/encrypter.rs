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

use auth_types::*;

pub trait Encrypter {
    // Encrypt data
    fn encrypt(&self, data: &[u8]) -> AuthResult<Vec<u8>>;

    /// Seal data to digital envelope
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice that should be encrypted
    ///
    /// # Description
    ///
    /// Digital envelope = {
    ///     asymmetric_encrypted_key,
    ///     encrypted_data,
    ///     encrypted_data_cmac
    ///     initial_vector,
    ///     additional_authentication_data
    /// }
    ///
    /// 1. Random symmetric key
    /// 2. Encrypt data using AEAD algorithm with symmetric key(step 1)
    /// 3. Encrypt symmetric key using asymmetric public key

    fn seal_digital_envelope(
        &self,
        data: &[u8],
    ) -> AuthResult<auth_manager_tonic::sdc::AsymmetricSecret>;
}
