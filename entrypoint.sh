#!/bin/sh

CONF_FILE="/etc/clamd.d/scan.conf"
[ -f /etc/clamd.conf ] && CONF_FILE="/etc/clamd.conf"
[ -f /etc/clamav/clamd.conf ] && CONF_FILE="/etc/clamav/clamd.conf"

# Replace values with environment variables in clamd.conf
sed -i 's/^#MaxScanSize .*$/MaxScanSize '"$MAX_SCAN_SIZE"'/g' "$CONF_FILE"
sed -i 's/^#StreamMaxLength .*$/StreamMaxLength '"$MAX_FILE_SIZE"'/g' "$CONF_FILE"
sed -i 's/^#MaxFileSize .*$/MaxFileSize '"$MAX_FILE_SIZE"'/g' "$CONF_FILE"
sed -i 's/^#MaxRecursion .*$/MaxRecursion '"$MAX_RECURSION"'/g' "$CONF_FILE"
sed -i 's/^#MaxFiles .*$/MaxFiles '"$MAX_FILES"'/g' "$CONF_FILE"
sed -i 's/^#MaxEmbeddedPE .*$/MaxEmbeddedPE '"$MAX_EMBEDDEDPE"'/g' "$CONF_FILE"
sed -i 's/^#MaxHTMLNormalize .*$/MaxHTMLNormalize '"$MAX_HTMLNORMALIZE"'/g' "$CONF_FILE"
sed -i 's/^#MaxHTMLNoTags.*$/MaxHTMLNoTags '"$MAX_HTMLNOTAGS"'/g' "$CONF_FILE"
sed -i 's/^#MaxScriptNormalize .*$/MaxScriptNormalize '"$MAX_SCRIPTNORMALIZE"'/g' "$CONF_FILE"
sed -i 's/^#MaxZipTypeRcg .*$/MaxZipTypeRcg '"$MAX_ZIPTYPERCG"'/g' "$CONF_FILE"
sed -i 's/^#MaxPartitions .*$/MaxPartitions '"$MAX_PARTITIONS"'/g' "$CONF_FILE"
sed -i 's/^#MaxIconsPE .*$/MaxIconsPE '"$MAX_ICONSPE"'/g' "$CONF_FILE"
sed -i 's/^#PCREMatchLimit.*$/PCREMatchLimit '"$PCRE_MATCHLIMIT"'/g' "$CONF_FILE"
sed -i 's/^#PCRERecMatchLimit .*$/PCRERecMatchLimit '"$PCRE_RECMATCHLIMIT"'/g' "$CONF_FILE"
sed -i 's/^#ConcurrentDatabaseReload yes/ConcurrentDatabaseReload no/g' "$CONF_FILE"

freshclam --daemon --checks=$SIGNATURE_CHECKS &
clamd &
/usr/bin/clamav-rest &

# Start the YARA/Maldet signature updater loop in the background (every 12 hours)
(while true; do sleep 43200; /usr/bin/update_signatures.sh; done) &

pids=`jobs -p`

exitcode=0

terminate() {
    for pid in $pids; do
        if ! kill -0 $pid 2>/dev/null; then
            wait $pid
            exitcode=$?
        fi
    done
    kill $pids 2>/dev/null
}

trap terminate CHLD
wait

exit $exitcode