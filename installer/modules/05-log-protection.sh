#!/usr/bin/env bash

module_05_log_protection() {
    log "Setting up log disk protection with loop-mounted images..."

    local IMG_DIR="/srv/images"
    declare -A DIR_SIZES=(
        ["/var/log/suricata"]="20G"
        ["/var/log/slips"]="10G"
        ["/var/lib/redis"]="5G"
        ["/opt/StratosphereLinuxIPS/output"]="5G"
    )
    local FSTAB_OPTS="loop,nodev,nosuid,nofail"

    mkdir -p "$IMG_DIR"

    if ! command -v rsync &> /dev/null; then
        log "Installing rsync..."
        apt-get update && apt-get install -y rsync || handle_error "Failed to install rsync"
    fi

    for D in "${!DIR_SIZES[@]}"; do
        local SZ="${DIR_SIZES[$D]}"
        local SAFE_NAME=$(echo "$D" | tr '/' '_' | sed 's/^_//')
        local IMG="$IMG_DIR/${SAFE_NAME}.img"
        local TEMP="/mnt/temp_${SAFE_NAME}"

        log "Creating ${SZ} image for $D at $IMG"
        
        fallocate -l "$SZ" "$IMG" || handle_error "Failed to create image $IMG"
        mkfs.ext4 -F "$IMG" || handle_error "Failed to format image $IMG"
        
        mkdir -p "$TEMP"
        mount -o loop "$IMG" "$TEMP" || handle_error "Failed to mount $IMG to $TEMP"

        mkdir -p "$D"
        if [ -d "$D" ] && [ "$(ls -A $D 2>/dev/null)" ]; then
            log "Copying existing data from $D to image"
            rsync -aAX --numeric-ids "$D/" "$TEMP/" 2>/dev/null || warn "rsync for $D had errors (may be empty)"
        fi
        
        umount "$TEMP"
        rmdir "$TEMP"

        if mountpoint -q "$D" 2>/dev/null; then
            umount "$D" || warn "Could not unmount $D"
        fi

        if [ -d "$D" ] && [ ! -L "$D" ]; then
            mv "$D" "${D}.old" 2>/dev/null || warn "Could not backup $D to ${D}.old"
        fi

        mkdir -p "$D"
        mount -o loop "$IMG" "$D" || handle_error "Failed to mount $IMG to $D"

        if ! grep -qF "$IMG $D" /etc/fstab; then
            echo "$IMG $D ext4 $FSTAB_OPTS 0 2" >> /etc/fstab
            log "Added $D to /etc/fstab"
        fi

        success "Mounted $IMG at $D"
    done

    success "Log disk protection configured (40GB contained)"
}

module_05_log_protection_info() {
    cat << EOF
Module: Log Disk Protection
Purpose: Create loop-mounted images for logs to prevent disk exhaustion
Actions:
  - Create 20GB image for /var/log/suricata
  - Create 10GB image for /var/log/slips
  - Create 5GB image for /var/lib/redis
  - Create 5GB image for /opt/StratosphereLinuxIPS/output
  - Add fstab entries for auto-mount
  - Preserve existing data in *.old directories
EOF
}
