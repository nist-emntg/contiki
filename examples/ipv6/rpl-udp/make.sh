make TARGET=native clean &&\
make TARGET=native CERTIFICATE=1 SERVER_REPLY=1  AKM_DEBUG=1 udp-client && \
make TARGET=native CERTIFICATE=1 DODAG_ROOT=1 SERVER_REPLY=1 AKM_DEBUG=1 udp-server

