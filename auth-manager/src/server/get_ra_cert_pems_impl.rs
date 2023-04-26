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
use crate::utils::crypto::sha::*;
use crate::{server::constant::SEPARATOR, unified_attestation_wrapper::*};
use auth_manager_tonic::sdc::{
    dataagent::*, UnifiedAttestationReport, UnifiedAttestationReportParams,
};
use auth_types::*;
use hex::encode_upper;

impl AuthManagerImpl {
    pub async fn get_ra_cert_pems_impl(
        &self,
        request: GetRaCertPemsRequest,
    ) -> AuthResult<Vec<ReportWithCertPem>> {
        let mut report_with_certs: Vec<ReportWithCertPem> = vec![];
        // the fixed data
        let tee_identity: &str = "1";
        let hex_report_type = "Passport".to_string();
        // generate one report for every nonce
        for nonce in request.nonces.iter() {
            let attestation_report: Option<UnifiedAttestationReport> = match self.mode.as_str() {
                // get RA report
                "production" => {
                    let data =
                        [self.kek_pub.as_bytes(), nonce.as_bytes()].join(SEPARATOR.as_bytes());
                    // fill report params
                    let report_params = UnifiedAttestationReportParams {
                        str_report_identity: "".to_owned(),
                        hex_user_data: encode_upper(sha256(&data)),
                        json_nested_reports: "".to_owned(),
                        hex_spid: "".to_owned(),
                    };

                    let report_json = runified_attestation_generate_auth_report(
                        tee_identity,
                        hex_report_type.as_str(),
                        "",
                        serde_json::to_string(&report_params)
                            .map_err(|e| {
                                errno!(
                                    AuthStatus::InternalErr,
                                    "report_params {:?} to json err: {:?}",
                                    &report_params,
                                    e
                                )
                            })?
                            .as_str(),
                    )
                    .map_err(|e| {
                        errno!(
                            AuthStatus::InternalErr,
                            "runified_attestation_generate_auth_report err: {:?}",
                            e
                        )
                    })?;
                    Some(serde_json::from_str(report_json.as_str()).map_err(|e| {
                        errno!(
                            AuthStatus::InternalErr,
                            "json {:?} to attentation_report err: {:?}",
                            &report_json,
                            e
                        )
                    })?)
                }
                // simulation mode doesn't need report
                "simulation" => None,
                _ => {
                    return Err(errno!(
                        AuthStatus::InvalidArgument,
                        "mode {} not supported",
                        &self.mode
                    ))
                }
            };

            let cert: ReportWithCertPem = ReportWithCertPem {
                secret_shard_id: 0,
                cert_pem: self.kek_pub.clone(),
                nonce: nonce.clone(),
                aecs_tee_signature: "".to_owned(),
                aecs_tee_pubkey: "".to_owned(),
                attestation_report,
            };
            report_with_certs.push(cert);
        }
        Ok(report_with_certs)
    }
}
