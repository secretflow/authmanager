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

use std::fmt;
use thiserror::Error;

use crate::retcode::*;

// define error type of authmanager
#[derive(Error, Debug, Copy, Clone, PartialEq)]
pub enum AuthStatus {
    #[error("Auth success")]
    Success,

    #[error("system error")]
    SystemErr,

    #[error("std::char::from_digit return None")]
    OptionNoneErr,

    #[error("unified attestation library error: {}", errcode)]
    UnifiedAttErr { errcode: i32 },

    #[error("internal error")]
    InternalErr,

    #[error("crypto error")]
    CryptoErr,

    #[error("unauthenticated")]
    Unauthenticated,

    #[error("assert err")]
    AssertErr,

    #[error("Invalid Argument")]
    InvalidArgument,

    #[error("Permission Denied")]
    PermissionDenied,

    #[error("already existed")]
    AlreadyExists,
}

pub fn map_authstatus_to_i32(err: AuthStatus) -> i32 {
    match err {
        AuthStatus::Success => AuthStatusT::Success as i32,
        AuthStatus::InternalErr => AuthStatusT::Internal as i32,
        AuthStatus::Unauthenticated => AuthStatusT::Unauthenticated as i32,
        AuthStatus::AlreadyExists => AuthStatusT::AlreadyExists as i32,
        _ => AuthStatusT::Unknown as i32,
    }
}

pub type AuthResult<T> = core::result::Result<T, Error>;

#[macro_export]
macro_rules! auth_assert {
    ($cond: expr, $($arg:tt)*) => {{
        if !$cond {
            return_errno!(AuthStatus::AssertErr, $($arg)*)
        }
    }}
}

#[macro_export]
macro_rules! auth_assert_eq {
    ($left:expr, $right:expr) => {{
        auth_assert!(
            $left == $right,
            "{} not equal to {}",
            stringify!($left),
            stringify!($right)
        );
    }};
}

#[macro_export]
macro_rules! auth_assert_ge {
    ($left:expr, $right:expr) => {{
        auth_assert!(
            ($left >= $right),
            "{} not large than {}",
            stringify!($left),
            stringify!($right)
        );
    }};
}

#[macro_export]
macro_rules! auth_assert_true {
    ($cond:expr) => {{
        auth_assert!($cond, "{} is false.", stringify!($cond));
    }};
}

#[macro_export]
macro_rules! auth_assert_false {
    ($cond:expr) => {{
        auth_assert!(!$cond, "{} is true.", stringify!($cond));
    }};
}

#[macro_export]
macro_rules! errno {
    ($errno_expr: expr, $($arg:tt)*) => {{
        let inner_error = {
            let errno: AuthStatus = $errno_expr;
            let msg: String = format!($($arg)*);
            (errno, msg)
        };
        let error = Error::embedded(inner_error, Some(ErrorLocation::new(file!(), line!())));
        error
    }};
}

#[macro_export]
macro_rules! return_errno {
    ($errno_expr: expr, $($arg:tt)*) => {{
        return Err(errno!($errno_expr, $($arg)*));
    }};
}

#[derive(Debug)]
pub struct Error {
    inner: Error__,
    location: Option<ErrorLocation>,
    cause: Option<Box<Error>>,
}

#[derive(Debug)]
enum Error__ {
    Embedded((AuthStatus, String)),
}

#[derive(Debug, Clone, Copy)]
pub struct ErrorLocation {
    line: u32,
    file: &'static str,
}

impl Error {
    pub fn embedded(inner: (AuthStatus, String), location_para: Option<ErrorLocation>) -> Error {
        Error {
            inner: Error__::Embedded(inner),
            location: location_para,
            cause: None,
        }
    }

    pub fn errno(&self) -> AuthStatus {
        match &self.inner {
            Error__::Embedded((errno, _)) => *errno,
        }
    }

    pub fn get_cause_mut(&mut self) -> &mut Option<Box<Error>> {
        &mut self.cause
    }

    pub fn get_cause(&self) -> &Option<Box<Error>> {
        &self.cause
    }
}

impl ErrorLocation {
    pub fn new(file_para: &'static str, line_para: u32) -> ErrorLocation {
        ErrorLocation {
            file: file_para,
            line: line_para,
        }
    }
}

impl std::error::Error for Error {
    /*fn description(&self) -> &str {
        self.errno().as_str()
    }*/

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.cause.as_ref().map(|e| e as &dyn std::error::Error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "inner: {}; ", self.inner)?;
        if let Some(location) = self.location {
            write!(f, "location: {}", location)?;
        }
        Ok(())
    }
}

impl fmt::Display for Error__ {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error__::Embedded((errno, msg)) => write!(f, "errno: {}, {}", errno, msg),
        }
    }
}

impl fmt::Display for ErrorLocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[line = {}, file = {}]", self.line, self.file)
    }
}
