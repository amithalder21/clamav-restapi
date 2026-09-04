#!/bin/sh

echo "[YARA/Maldet Updater] Starting signature update..."

# 1. Update Maldet
echo "[YARA/Maldet Updater] Updating Maldet signatures and engine..."
maldet -u
maldet -d

# 2. Update YARA Rules (Florian Roth's signature-base fork)
YARA_DIR="/var/lib/yara_rules/signature-base"
if [ -d "$YARA_DIR/.git" ]; then
    echo "[YARA/Maldet Updater] Pulling latest YARA rules from GitHub..."
    cd $YARA_DIR && git pull
else
    echo "[YARA/Maldet Updater] Cloning YARA rules from GitHub..."
    git clone https://github.com/amithalder21/signature-base.git $YARA_DIR
fi

# 3. Compile YARA index
echo "[YARA/Maldet Updater] Rebuilding YARA index.yar..."
cd $YARA_DIR
# Find all .yar and .yara files and create an include list.
find ./yara -type f \( -name "*.yar" -o -name "*.yara" \) -exec echo "include \"signature-base/{}\"" \; > /var/lib/yara_rules/index.yar

# 4. Recompile YARA rules to bytecode (RunYaraScan scans against compiled.yarc,
# not index.yar, so the app keeps using pre-update rules until this runs).
# External variables must be re-declared here to match RunYaraScan's -d flags.
echo "[YARA/Maldet Updater] Recompiling YARA rules to compiled.yarc..."
cd /var/lib/yara_rules
yarac -d filename="" -d filepath="" -d extension="" -d owner="" -d filetype="" index.yar compiled.yarc.new \
    && mv compiled.yarc.new compiled.yarc \
    || echo "[YARA/Maldet Updater] WARNING: yarac compile failed, keeping previous compiled.yarc"

echo "[YARA/Maldet Updater] Signature update complete."
