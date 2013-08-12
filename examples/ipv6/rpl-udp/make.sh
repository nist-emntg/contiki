make TARGET=native clean
make TARGET=native SERVER_REPLY=1 NODE_KEY_CACHE_SIZE=4 udp-client
make TARGET=native clean
make TARGET=native DODAG_ROOT=1 SERVER_REPLY=1 NODE_KEY_CACHE_SIZE=8 udp-server

