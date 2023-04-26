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

mod secretflow {
    tonic::include_proto!("secretflowapis.v1");
    pub mod sdc {
        tonic::include_proto!("secretflowapis.v1.sdc");
        pub mod authmanager {
            tonic::include_proto!("secretflowapis.v1.sdc.authmanager");
        }
        pub mod dataagent {
            tonic::include_proto!("secretflowapis.v1.sdc.dataagent");
        }
        pub mod teeapps {
            tonic::include_proto!("secretflowapis.v1.sdc.teeapps");
        }
    }
}

pub use crate::secretflow::*;
