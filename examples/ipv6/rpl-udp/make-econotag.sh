make TARGET=econotag clean &&\
make TARGET=econotag UIP_CONF_TCP=0 CERTIFICATE=1 SERVER_REPLY=1  udp-client && \
make TARGET=econotag UIP_CONF_TCP=0 CERTIFICATE=1 DODAG_ROOT=1 SERVER_REPLY=1 udp-server

