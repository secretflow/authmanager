#
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
#
#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
image=secretflow/capsule-manager-ci-ubuntu20.04:occlum0.29.5-0.1.0b
DOCKER=docker
project=authmanager-dev-ubuntu
if [[ $1 == 'enter' ]]; then
    sudo $DOCKER exec -it ${project}-build-ubuntu-$(whoami)-sgx2 bash
else
    sudo $DOCKER run --name ${project}-build-ubuntu-$(whoami)-sgx2 -td \
        --net host \
        -v /dev/sgx_enclave:/dev/sgx/enclave -v /dev/sgx_provision:/dev/sgx/provision \
        -v $DIR:/home/admin/dev \
        -v /root/${USER}-${project}-bazel-cache-test:/root/.cache/bazel \
        -w /home/admin/dev \
        --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
        --cap-add=NET_ADMIN \
        --privileged=true \
        ${image}
fi