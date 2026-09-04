# Builder stage
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o clamav-rest .

# Runtime stage
FROM rockylinux:9

RUN dnf -y upgrade --refresh \
    && dnf install -y epel-release \
    && dnf install -y clamav-server clamav-data clamav-update clamav-filesystem clamav clamav-scanner-systemd clamav-lib \
       yara wget tar gzip inotify-tools perl git \
    && mkdir -p /run/clamav \
    && (chown clamupdate:clamupdate /run/clamav 2>/dev/null || chown clamscan:clamscan /run/clamav) \
    && cd /tmp \
    && wget https://www.rfxn.com/downloads/maldetect-current.tar.gz \
    && tar -xzvf maldetect-current.tar.gz \
    && rm -f maldetect-current.tar.gz \
    && cd maldetect-* \
    && sh install.sh \
    && maldet -u -d \
    && cd / \
    && rm -rf /tmp/maldetect* \
    && dnf clean -y all --enablerepo='*' \
    && rm -Rf /tmp/* \
    && ln -sf /usr/share/zoneinfo/Europe/Zurich /etc/localtime

# Configure clamAV to run in foreground with port 3310
# Also comment out Example in scan.conf and freshclam.conf
RUN sed -i 's/^Example$/# Example/g' /etc/clamd.d/scan.conf 2>/dev/null || true \
    && sed -i 's/^#Foreground .*$/Foreground true/g' /etc/clamd.d/scan.conf 2>/dev/null || true \
    && sed -i 's/^#TCPSocket .*$/TCPSocket 3310/g' /etc/clamd.d/scan.conf 2>/dev/null || true \
    && sed -i 's/^Example$/# Example/g' /etc/freshclam.conf 2>/dev/null || true \
    && sed -i 's/^#Foreground .*$/Foreground true/g' /etc/freshclam.conf 2>/dev/null || true

# If scan.conf doesn't exist (sometimes the package puts it in /etc/clamd.conf in rockylinux)
RUN [ -f /etc/clamd.conf ] && sed -i 's/^Example$/# Example/g' /etc/clamd.conf || true \
    && [ -f /etc/clamd.conf ] && sed -i 's/^#Foreground .*$/Foreground true/g' /etc/clamd.conf || true \
    && [ -f /etc/clamd.conf ] && sed -i 's/^#TCPSocket .*$/TCPSocket 3310/g' /etc/clamd.conf || true


RUN freshclam --quiet --no-dns

# Custom, non-EICAR ClamAV test signature (offset "*" = matches anywhere in
# the file) used to demonstrate position/padding independence separately
# from EICAR's own exact-68-byte-match design quirk (P2, 2026-09-01 AppSec
# report). freshclam only manages its own official CVD/CLD databases, so
# this custom .ndb is untouched by signature updates.
COPY test-signatures/local.ndb /var/lib/clamav/local.ndb

# Copy binary, certs, and YARA rules. Precompiling with yarac (-> compiled.yarc)
# means the app scans against ready-to-use bytecode instead of recompiling the
# entire multi-thousand-rule signature-base source tree from text on every
# single scan request. The external variables must be declared here (with
# placeholder values) so the compiled rules know about them; RunYaraScan
# supplies the real per-scan values via the same flags at scan time.
COPY --from=builder /src/clamav-rest /usr/bin/
COPY ssl/server.* /etc/ssl/clamav-rest/
RUN mkdir -p /var/lib/yara_rules && \
    git clone https://github.com/amithalder21/signature-base.git /var/lib/yara_rules/signature-base && \
    cd /var/lib/yara_rules && \
    find ./signature-base/yara -type f \( -name "*.yar" -o -name "*.yara" \) -exec echo "include \"{}\"" \; > index.yar && \
    yarac -d filename="" -d filepath="" -d extension="" -d owner="" -d filetype="" index.yar compiled.yarc

COPY entrypoint.sh /usr/bin/
COPY update_signatures.sh /usr/bin/
RUN chmod +x /usr/bin/entrypoint.sh /usr/bin/update_signatures.sh

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
ENV SIGNATURE_CHECKS=24

# Ensure entrypoint has right permissions in case clamd is looking at configs in /etc/clamav
# We might need to map variables to /etc/clamd.d/scan.conf instead of /etc/clamav/clamd.conf
# We will do this via a patch in entrypoint.sh later if needed, but for now we follow the original script
# which assumes /etc/clamav/clamd.conf exists. Wait, original centos.Dockerfile used /etc/clamd.d/scan.conf!
# Our entrypoint.sh hardcodes /etc/clamav/clamd.conf. We should fix entrypoint.sh to handle both.

ENTRYPOINT [ "entrypoint.sh" ]