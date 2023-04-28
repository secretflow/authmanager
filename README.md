[![CircleCI](https://dl.circleci.com/status-badge/img/gh/secretflow/authmanager/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/secretflow/authmanager/tree/main)

# AuthManager

AuthManager is a Authorization Management Service, which is designed to manage metadata of user data and authorization information. 

## Features

- AuthManager runs on the Intel SGX Machine, it will be remote attested by the user who uploads data to ensure that the AuthManager has no malicious behavior
- AuthManager uses signatures or mac, digital envelopes, etc. to prevent communication data from being tampered, and it also supports mtls
- AuthManager manages the data encryption keys and meta-informations. All services which want to get these information must be verified to have the authorization to obtain the data encryption keys and meta-informations, ensuring that the authorization semantics cannot be bypassed
- AuthManager supports flexible authorization semantics

## Build And Run By Source Code

there are two modes in the AuthManager: simulation mode, production mode

### Prepare

- First of all, we need to generate dynamic link library, libgeneration.so and libverification.
- Then, we need to move two librarys to the directory "second_party/unified_attestation/c/lib/"

so how to generate dynamic link library?

- get submodule in the current directory

```bash
git clone xxx
git submodule init
git submodule update --init
git submodule update --remote
```

until now, we pull code from github to the directory "second_party/apis/" and "second_party/unified-attestation/"

- get submodule in the directory "second_party/unified-attestation/"

```bash
cd second_party/unified-attestation/
git submodule init
git submodule update --init
git submodule update --remote --recursive
cd ../..
```

until now, we get all submodule in the AuthManager

- compile source code to get the above two dynamic link librarys

```bash
# create docker image
bash sgx2-env
# enter docker image
bash sgx2-env enter
cd second_party/unified-attestation/
bazel build //:libgeneration.so
bazel build //:libverification.so
cd ../..
# copy libgeneration.so libverification.so 
cp second_party/unified-attestation/bazel-bin/libgeneration.so second_party/unified_attestation/c/lib/
cp second_party/unified-attestation/bazel-bin/libverification.so second_party/unified_attestation/c/lib/
```


### Simulation Mode

Remote Attestation is not enabled for this mode

```bash
# build exe and occlum
MODE=SIM bash deployment/build.sh
# 
cd occlum_release
# enable tls(often skip)
# if you want to use the mtls, you can refer to the mtls part
# run service
# if the port is occupied, you can modify the field port in the config.yaml
occlum run /bin/auth-manager --config_path /host/config.yaml
```

### Production Mode(default mode)

Remote Attestation is enabled for this mode
NOTICE: if you modify any field in the configuration file in occlum release, you must execute command "occlum build -f --sign-key <path_to/your_key.pem>"

```bash
# build exe and occlum
bash deployment/build.sh
# 
cd occlum_release
# enable tls(often skip)
# if you want to use the mtls, you can refer to the mtls part
# connect to pccs service
modify /etc/sgx_default_qcnl.conf PCCS_UR
modify image/etc/kubetee/unified_attestation.json ua_dcap_pccs_url
# Generate a pair of public and private keys
occlum build -f --sign-key <path_to/your_key.pem>
# run service
occlum run /bin/auth-manager --config_path /host/config.yaml
```

## Run Quickly by Docker Image

there are two kinds of docker images, corresponding to simulation mode and production mode

### Simulation Mode Image

```bash
# pull docker image
docker pull xxxx
# enter docker image
sudo docker run -it --net host xxxx
#
cd occlum_release
# enable tls(often skip)
# if you want to use the mtls, you can refer to the mtls part
# run service
occlum run /bin/auth-manager --config_path /host/config.yaml
```

### Production Mode Image

```bash
# pull docker image
docker pull xxxx
# enter docker image
sudo docker run -it --net host -v /dev/sgx_enclave:/dev/sgx/enclave -v /dev/sgx_provision:/dev/sgx/provision --privileged=true xxxx
#
cd occlum_release
# enable tls(often skip)
# if you want to use the mtls, you can refer to the mtls part
# connect to pccs service
modify /etc/sgx_default_qcnl.conf PCCS_UR
modify occlum_release/image/etc/kubetee/unified_attestation.json ua_dcap_pccs_url
# Generate a pair of public and private keys
occlum build -f --sign-key <path_to/your_key.pem>
# run service
occlum run /bin/auth-manager --config_path /host/config.yaml
```

## Mutual Tls

you must generate certificate if you want to use mtls feature of AuthManager

- for AuthManager, all certificates should be put in the directory whose path is ”auth-manager/resources“
- for AuthManager, the required certificates are the Server Key, the Server Certificate, and the Client CA Certificate which is used to verify the Client Certificate
- for Client, the required certificates are the Client Key, the Client Certificate, and the Server CA Certificate which is used to verify the Server Certificate
- for AuthManager, you should modify the field server_cert_path, server_cert_key_path and client_ca_cert_path in the configuration file named config.yaml
- when all is ready, you can enable mtls by modifying the field enable_tls in the the configuration file named config.yaml to true

## Contributing

Please check [CONTRIBUTING.md](CONTRIBUTING.md)

## License

This project is licensed under the [Apache License](LICENSE)
