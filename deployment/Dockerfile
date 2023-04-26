FROM occlum/occlum:0.29.4-ubuntu20.04

USER root

COPY docker/sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf
COPY output /home/root/

EXPOSE 8835

WORKDIR /home/root/
