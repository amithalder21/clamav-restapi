# Builder stage
FROM golang:alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o clamav-rest .

# Runtime stage
FROM alpine:edge

# Set timezone
RUN apk add --no-cache tzdata \
    && ln -s /usr/share/zoneinfo/Europe/Zurich /etc/localtime

# Install ClamAV
RUN apk add --no-cache clamav clamav-libunrar \
    && mkdir -p /run/clamav \
    && chown clamav:clamav /run/clamav

# Configure clamAV to run in foreground with port 3310
RUN sed -i 's/^#Foreground .*$/Foreground true/g' /etc/clamav/clamd.conf \
    && sed -i 's/^#TCPSocket .*$/TCPSocket 3310/g' /etc/clamav/clamd.conf \
    && sed -i 's/^#Foreground .*$/Foreground true/g' /etc/clamav/freshclam.conf

RUN freshclam --quiet --no-dns

# Copy binary and certs
COPY --from=builder /src/clamav-rest /usr/bin/
COPY ./server.* /etc/ssl/clamav-rest/
COPY entrypoint.sh /usr/bin/
RUN chmod +x /usr/bin/entrypoint.sh

EXPOSE 9000
EXPOSE 9443

ENV MAX_SCAN_SIZE=100M
ENV MAX_FILE_SIZE=25M
ENV MAX_RECURSION=16
ENV MAX_FILES=10000
ENV MAX_EMBEDDEDPE=10M
ENV MAX_HTMLNORMALIZE=10M
ENV MAX_HTMLNOTAGS=2M
ENV MAX_SCRIPTNORMALIZE=5M
ENV MAX_ZIPTYPERCG=1M
ENV MAX_PARTITIONS=50
ENV MAX_ICONSPE=100
ENV PCRE_MATCHLIMIT=100000
ENV PCRE_RECMATCHLIMIT=2000
ENV SIGNATURE_CHECKS=2

ENTRYPOINT [ "entrypoint.sh" ]