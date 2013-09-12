make TARGET=native clean
make CC=gcc TARGET=native SERVER_REPLY=1  AKM_DEBUG=1 udp-client 
make TARGET=native clean
make CC=gcc TARGET=native DODAG_ROOT=1 SERVER_REPLY=1 AKM_DEBUG=1 udp-server

