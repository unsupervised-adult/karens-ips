#!/usr/bin/env bash
set -euo pipefail

IMG_DIR="/srv/images"
declare -A DIR_SIZES=(
  ["/var/log/suricata"]="20G"
  ["/var/log/slips"]="10G"
  ["/var/lib/redis"]="5G"
  ["/opt/StratosphereLinuxIPS/output"]="5G"
)
FSTAB_OPTS="loop,nodev,nosuid,nofail"

mkdir -p "$IMG_DIR"

if ! command -v rsync &> /dev/null; then
  echo "rsync not found. Installing..."
  apt-get update && apt-get install -y rsync
fi

for D in "${!DIR_SIZES[@]}"; do
  SZ="${DIR_SIZES[$D]}"
  SAFE_NAME=$(echo "$D" | tr '/' '_' | sed 's/^_//')
  IMG="$IMG_DIR/${SAFE_NAME}.img"
  TEMP="/mnt/temp_${SAFE_NAME}"

  echo "Creating image for $D of size $SZ at $IMG"
  fallocate -l "$SZ" "$IMG"
  mkfs.ext4 -F "$IMG"
  mkdir -p "$TEMP"
  mount -o loop "$IMG" "$TEMP"

  echo "Copying data from $D to $TEMP"
  mkdir -p "$D"
  rsync -aAX --numeric-ids "$D/" "$TEMP/" 2>/dev/null || echo "Warning: rsync for $D had errors (may be empty)"
  umount "$TEMP"
  rmdir "$TEMP"

  if mountpoint -q "$D" 2>/dev/null; then
    umount "$D" || echo "Warning: Could not unmount $D"
  fi

  if [ -d "$D" ] && [ ! -L "$D" ]; then
    mv "$D" "${D}.old" || echo "Warning: Could not rename $D"
  fi

  mkdir -p "$D"
  mount -o loop "$IMG" "$D"

  grep -F "$IMG $D" /etc/fstab || \
    echo "$IMG $D ext4 $FSTAB_OPTS 0 2" >> /etc/fstab

  echo "Mounted $IMG at $D"
done

echo "All log directories migrated to loopback images."
echo "Old data preserved in *.old directories."
echo "System will use contained log images to prevent disk exhaustion."
