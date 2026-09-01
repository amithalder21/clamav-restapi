docker run --rm alpine:3.18 sh -c "
apk add curl automake libtool make gcc musl-dev openssl-dev jansson-dev libmagic file-dev && \
curl -sL https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.2.tar.gz | tar -xz && \
cd yara-4.3.2 && \
./bootstrap.sh && \
./configure --enable-magic --enable-cuckoo && \
make -j4 && \
make install && \
yara -v
"
