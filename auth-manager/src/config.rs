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

use std::fs;

use clap::{App, Arg};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// listening port
    pub port: u32,
    /// log config
    pub log_config: LogConfig,
    /// remote storage client config
    pub remote_storage_client_config: RemoteStorageClientConfig,
    /// key scheme: SM2, RSA
    pub scheme: String,
    //  the secret shard ID this service handled
    pub secret_shard_id: i32,
    // the mod of authmanager
    pub mode: Option<String>,
    // the storage backend
    pub storage_backend: String,
    // secret key pair from
    pub secret_key_from: String,
    // server cert path
    pub server_cert_path: String,
    // server cert key path
    pub server_cert_key_path: String,
    // root ca cert path
    pub client_ca_cert_path: String,
    // enable mtls
    pub enable_tls: bool,
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LogConfig {
    /// log file name
    pub log_file_name: String,
    /// monitor log file name
    pub monitor_log_file_name: String,
    /// log level
    pub log_level: String,
    /// enable console logger
    pub enable_console_logger: bool,
    /// log window size
    pub log_window_size: u32,
    /// log size limit, MB
    pub log_size_limit: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RemoteStorageClientConfig {
    /// remote storage endpoint
    pub remote_storage_endpoint: String,
}

impl Config {
    pub fn new() -> Self {
        // Parse whole args with clap
        let mut config_path = String::from("config.yaml");
        let seapp = App::new("AuthManager").version("1.0").about("AuthManager");
        let config_path_option = Arg::with_name("config_path")
            .long("config_path")
            .takes_value(true)
            .help("config path")
            .required(false);
        let app = seapp.arg(config_path_option);
        let matches = app.get_matches();
        if let Some(parm) = matches.value_of("config_path") {
            config_path = String::from(parm);
        }
        let yaml = fs::read_to_string(&config_path).unwrap();
        let mut config: Config = serde_yaml::from_str(&yaml).unwrap();
        // set mode according to cfg
        if cfg!(feature = "production") {
            config.mode = Some("production".to_owned());
        } else {
            config.mode = Some("simulation".to_owned());
        }
        config
    }
}
