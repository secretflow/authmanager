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

mod config;

use std::{
    fs::{self},
    str::{from_utf8, FromStr},
};

use auth_manager::{server::AuthManagerImpl, utils::crypto::scheme::AsymmetricScheme};
use auth_manager_tonic::sdc::authmanager::auth_manager_server::AuthManagerServer;

use config::LogConfig;
use log::{info, LevelFilter};
use tonic::transport::Server;

// init log
fn init_log(log_config: &LogConfig) {
    use log4rs::append::console::ConsoleAppender;
    use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
    use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
    use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
    use log4rs::append::rolling_file::RollingFileAppender;
    use log4rs::config::{Appender, Config, Logger, Root};
    use log4rs::encode::pattern::PatternEncoder;

    let log_level = if log_config.log_level.as_ref().unwrap() == "debug" {
        LevelFilter::Debug
    } else if log_config.log_level.as_ref().unwrap() == "info" {
        LevelFilter::Info
    } else if log_config.log_level.as_ref().unwrap() == "warn" {
        LevelFilter::Warn
    } else if log_config.log_level.as_ref().unwrap() == "error" {
        LevelFilter::Error
    } else {
        LevelFilter::Debug
    };

    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("[{d}] [{t}] [{l}] {m}{n}")))
        .build();

    let fixed_window_roller = FixedWindowRoller::builder()
        .build(
            &(log_config.log_file_name.clone().unwrap() + ".{}"),
            log_config.log_window_size.unwrap(),
        )
        .unwrap();
    let size_trigger = SizeTrigger::new(log_config.log_size_limit.unwrap() * 1024 * 1024);
    let compound_policy =
        CompoundPolicy::new(Box::new(size_trigger), Box::new(fixed_window_roller));
    let authmanager_log = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("[{d}] [{t}] [{l}] {m}{n}")))
        .build(
            log_config.log_file_name.as_ref().unwrap(),
            Box::new(compound_policy),
        )
        .unwrap();

    let fixed_window_roller = FixedWindowRoller::builder()
        .build(
            &(log_config.monitor_log_file_name.clone().unwrap() + ".{}"),
            log_config.log_window_size.unwrap(),
        )
        .unwrap();
    let compound_policy =
        CompoundPolicy::new(Box::new(size_trigger), Box::new(fixed_window_roller));
    let monitor_log = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("[{d}] [{t}] [{l}] {m}{n}")))
        .build(
            log_config.monitor_log_file_name.as_ref().unwrap(),
            Box::new(compound_policy),
        )
        .unwrap();

    let mut root_builder = Root::builder().appender("authmanager_log");
    if log_config.enable_console_logger.unwrap() {
        root_builder = root_builder.appender("stdout");
    }

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .appender(Appender::builder().build("monitor_log", Box::new(monitor_log)))
        .appender(Appender::builder().build("authmanager_log", Box::new(authmanager_log)))
        .logger(
            Logger::builder()
                .appender("monitor_log")
                .build("monitor", log_level),
        )
        .build(root_builder.build(log_level))
        .expect("failed to build log config");

    log4rs::init_config(config).expect("failed to init log");
}

#[tokio::main(worker_threads = 16)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse whole args with clap
    let cfg = config::Config::new();
    let remote_storage_config = &cfg.remote_storage_client_config;

    // init log
    init_log(&(LogConfig::from(cfg.log_config)));
    info!(
        "remote endpoint {:?}",
        remote_storage_config.remote_storage_endpoint
    );

    let addr = format!("0.0.0.0:{}", cfg.port.unwrap()).parse()?;
    let auth_manager = AuthManagerImpl::new(
        remote_storage_config
            .remote_storage_endpoint
            .as_ref()
            .unwrap()
            .as_str(),
        cfg.secret_shard_id.unwrap(),
        AsymmetricScheme::from_str(cfg.scheme.as_ref().unwrap().as_str()).unwrap(),
        &cfg.mode.as_ref().unwrap().as_str(),
        &cfg.storage_backend.as_ref().unwrap().as_str(),
        &cfg.secret_key_from.as_ref().unwrap().as_str(),
    );

    info!("Server run at: {:?} mode {:?}", addr, cfg.mode);
    if cfg.enable_tls.unwrap() {
        // Configure the server certificate for the client to verify the server
        let svr_cert = fs::read_to_string(cfg.server_cert_path.as_ref().unwrap()).unwrap();
        let svr_key = fs::read_to_string(cfg.server_cert_key_path.as_ref().unwrap()).unwrap();
        let id = tonic::transport::Identity::from_pem(svr_cert.as_bytes(), svr_key.as_bytes());
        // Configure the client CA certificate to verify the client certificate
        let mut client_pem_vec: Vec<u8> = vec![];
        for entry in fs::read_dir(cfg.client_ca_cert_path.as_ref().unwrap())? {
            let path = entry?.path();
            let mut client_ca_pem = fs::read_to_string(&path).unwrap().as_bytes().to_vec();
            client_pem_vec.append(&mut client_ca_pem);
        }

        let client_ca_cert = tonic::transport::Certificate::from_pem(client_pem_vec);
        let tls_config = tonic::transport::ServerTlsConfig::new()
            .identity(id)
            .client_ca_root(client_ca_cert);
        Server::builder()
            .tls_config(tls_config)?
            .add_service(AuthManagerServer::new(auth_manager))
            .serve(addr)
            .await?;
    } else {
        Server::builder()
            .add_service(AuthManagerServer::new(auth_manager))
            .serve(addr)
            .await?;
    }

    Ok(())
}
