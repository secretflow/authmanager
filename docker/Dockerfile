# Copyright 2023 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM occlum/occlum:0.29.4-ubuntu20.04

LABEL maintainer="secretflow-contact@service.alipay.com"

USER root:root
ENV TZ=Asia/Shanghai

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

COPY sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf

# install rust
RUN rustup self uninstall -y
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y
RUN curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C ${CARGO_HOME:-~/.cargo}/bin
RUN apt-get update
RUN apt-get install -y cmake ninja-build nasm
RUN wget https://github.com/bazelbuild/bazel/releases/download/5.4.0/bazel-5.4.0-installer-linux-x86_64.sh \
    && bash ./bazel-5.4.0-installer-linux-x86_64.sh && rm -f ./bazel-5.4.0-installer-linux-x86_64.sh
# run as root for now
WORKDIR /home/admin/