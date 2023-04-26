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
use serde::Deserialize;
use std::str::FromStr;

// constant define
pub const RSA_BIT_LEN: u32 = 3072;
// pub const UA_REPORT_SIZE_BGCHECK: u32 = 8192;
pub const UA_REPORT_SIZE_PASSPORT: u32 = 20480;
// pub const UA_REPORT_SIZE_UAS: u32 = 8192;
pub const ALLOWED_ALL: &str = "all";
pub const SEPARATOR: &str = "|";

// DataSource
// USER: data from institution
// TEE: data from TEE-worker which means it's intermediate data calculated by TEE
#[derive(PartialEq)]
pub(crate) enum SourceType {
    Tee,
    User,
}

impl FromStr for SourceType {
    type Err = auth_types::Error;
    // case insensitive
    fn from_str(input: &str) -> AuthResult<SourceType> {
        match input.to_uppercase().as_str() {
            "TEE" => Ok(SourceType::Tee),
            "USER" => Ok(SourceType::User),
            _ => Err(errno!(
                AuthStatus::InvalidArgument,
                "unknown source type: {}",
                input
            )),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ExtraLimits {
    pub limit_functions: Vec<String>,
}
