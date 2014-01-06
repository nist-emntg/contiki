export MAX_ID=2
make TARGET=econotag clean &&\
make DEFINES=M12_CONF_SERIAL=99 TARGET=econotag UIP_CONF_TCP=0 CERTIFICATE=1 DODAG_ROOT=1 SERVER_REPLY=1  udp-server &&\
mv udp-server_econotag.bin udp-server_econotag.flash && \
for i in `seq 1 $MAX_ID`; do
    make TARGET=econotag clean &&\
    make DEFINES=M12_CONF_SERIAL=$i TARGET=econotag UIP_CONF_TCP=0 CERTIFICATE=1 SERVER_REPLY=1  udp-client &&\
    mv udp-client_econotag.bin udp-client_econotag-$i.flash
done
mv udp-server_econotag.flash udp-server_econotag.bin
for i in `seq 1 $MAX_ID`; do
    mv udp-client_econotag-$i.flash udp-client_econotag-$i.bin
done
