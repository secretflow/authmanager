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

#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug)]
pub enum AuthStatusT {
    // 通用错误码，预留000-099
    // 0 ～ 16 目前对应错误码
    Success = 0,
    CANCELLED = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
    // 从 100 开始为自定义错误码
    // Unified Attestation Error
    UnifiedAttErr = 100,
    // Data Agent Request Error
    DataAgentErr = 200,
}

impl AuthStatusT {
    pub fn as_str(&self) -> &str {
        match *self {
            AuthStatusT::Success => "Success",
            AuthStatusT::CANCELLED => todo!(),
            AuthStatusT::Unknown => todo!(),
            AuthStatusT::InvalidArgument => todo!(),
            AuthStatusT::DeadlineExceeded => todo!(),
            AuthStatusT::NotFound => todo!(),
            AuthStatusT::AlreadyExists => todo!(),
            AuthStatusT::PermissionDenied => todo!(),
            AuthStatusT::ResourceExhausted => todo!(),
            AuthStatusT::FailedPrecondition => todo!(),
            AuthStatusT::Aborted => todo!(),
            AuthStatusT::OutOfRange => todo!(),
            AuthStatusT::Unimplemented => todo!(),
            AuthStatusT::Internal => todo!(),
            AuthStatusT::Unavailable => todo!(),
            AuthStatusT::DataLoss => todo!(),
            AuthStatusT::Unauthenticated => todo!(),
            AuthStatusT::UnifiedAttErr => todo!(),
            AuthStatusT::DataAgentErr => todo!(),
        }
    }
}
