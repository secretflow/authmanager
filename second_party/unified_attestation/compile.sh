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

workdir=$(cd $(dirname $0); pwd)
CRTDIR=$(pwd)
cd $workdir/../unified-attestation/
git submodule init
git submodule update --init
git submodule update --remote --recursive
bazelisk build //:libgeneration.so
bazelisk build //:libverification.so
cd ..
if [ ! -d "unified_attestation/c/lib/" ]; then
    mkdir -p unified_attestation/c/lib/
fi
cp unified-attestation/bazel-bin/libgeneration.so unified_attestation/c/lib/ -f
cp unified-attestation/bazel-bin/libverification.so unified_attestation/c/lib/ -f
cd $CRTDIR