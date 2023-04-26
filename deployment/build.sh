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
set -ex

GREEN="\033[32m"
NO_COLOR="\033[0m"

# cd work dir
SCRIPT=$(readlink -f "$0")
SCRIPT_DIR=$(dirname "$SCRIPT")
WORK_SPACE_DIR=$SCRIPT_DIR/..

pushd $WORK_SPACE_DIR
if [ $MODE -a "$MODE" == "SIM" ]; then
   CARGO_TARGET_DIR=auth-target cargo build --release
else
   CARGO_TARGET_DIR=auth-target cargo build --features production --release
fi

rm -rf occlum_release
mkdir occlum_release
cd occlum_release
occlum init

# Copy glibc so to image.
cp /opt/occlum/glibc/lib/libdl*.so* image/opt/occlum/glibc/lib/
cp /opt/occlum/glibc/lib/librt*.so* image/opt/occlum/glibc/lib/
#DNS
cp /opt/occlum/glibc/lib/libnss_dns.so.2    \
   /opt/occlum/glibc/lib/libnss_files.so.2  \
   /opt/occlum/glibc/lib/libresolv.so.2     \
   image/opt/occlum/glibc/lib/

cp ../auth-target/release/auth-manager image/bin/auth-manager
cp ../deployment/conf/Occlum_sgx2.json Occlum.json
cp ../deployment/conf/config.yaml config.yaml
mkdir -p image/etc/kubetee/
cp ../deployment/conf/unified_attestation.json image/etc/kubetee/unified_attestation.json
cp ../second_party/unified_attestation/c/lib/* image/lib/
cp ../deployment/bin/gen_mrenclave.sh gen_mrenclave.sh
if [ ! -d "../auth-manager/resources" ]; then
  mkdir ../auth-manager/resources
fi
cp -r ../auth-manager/resources resources

if [ $MODE -a "$MODE" == "SIM" ]; then
   SGX_MODE=SIM occlum build -f
elif [ -z $KEY_PATH ]; then
   echo "KEY_PATH not found, will use default key"
   occlum build -f
else
   occlum build --sign-key $KEY_PATH
fi
