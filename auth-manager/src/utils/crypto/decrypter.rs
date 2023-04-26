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
pub trait Decrypter {
    // Decrypt data
    fn decrypt(&self, data: &[u8]) -> AuthResult<Vec<u8>>;
    /// Open data from digital envelope
    ///
    /// # Arguments
    ///
    /// * `envelope` - digital envelope
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
    /// 1. Decrypt symmetric key using asymmetric private key
    /// 2. Decrypt data using AEAD algorithm with symmetric key(step 1)
    fn open_digital_envelope(
        &self,
        envelope: &auth_manager_tonic::sdc::AsymmetricSecret,
    ) -> AuthResult<Vec<u8>>;
}
