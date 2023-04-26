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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // compile protobuf
    tonic_build::configure()
        .type_attribute(
            "UnifiedAttestationReportParams",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute("UnifiedAttestationReportParams", "#[serde(default)]")
        .type_attribute(
            "UnifiedAttestationAttributes",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute("UnifiedAttestationAttributes", "#[serde(default)]")
        .type_attribute(
            "UnifiedAttestationNestedPolicy",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute("UnifiedAttestationNestedPolicy", "#[serde(default)]")
        .type_attribute(
            "UnifiedAttestationPolicy",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute("UnifiedAttestationPolicy", "#[serde(default)]")
        .type_attribute(
            "UnifiedAttestationReport",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .type_attribute("UnifiedAttestationReport", "#[serde(default)]")
        .compile(
            &[
                "../second_party/apis/secretflowapis/v1/sdc/authmanager/auth_manager.proto",
                "../second_party/apis/secretflowapis/v1/sdc/dataagent/data_agent.proto",
            ],
            &["../second_party/apis"], // specify the root location to search proto dependencies
        )?;
    Ok(())
}
