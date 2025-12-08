#!/bin/bash
# Monitor YouTube ad patterns in real-time
# Watches for the characteristic timing sequence: content → ad decisioning → ad playback

echo "════════════════════════════════════════════════════════════════"
echo "YouTube Ad Pattern Monitor"
echo "Watching for: Content (3-10s) → DAI (10-20s midroll ad)"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "Press Ctrl+C to stop"
echo ""

# Watch Redis for new detections
redis-cli -n 1 SUBSCRIBE ml_detector:new_detection 2>/dev/null &
REDIS_PID=$!

# Monitor stream-ad-blocker logs in real-time
journalctl -fu stream-ad-blocker -n 0 | while read line; do
    timestamp=$(echo "$line" | awk '{print $1, $2, $3}')
    
    # Highlight different detection types
    if echo "$line" | grep -q "YOUTUBE AD FLOW DROPPED"; then
        echo -e "${RED}[AD FLOW DROP]${NC} $timestamp - $line"
    elif echo "$line" | grep -q "AD CONTROL BLOCK"; then
        echo -e "${YELLOW}[AD CONTROL]${NC} $timestamp - $line"
    elif echo "$line" | grep -q "quic_bumper\|quic_skippable\|quic_midroll\|ad_pod"; then
        echo -e "${BLUE}[AD PATTERN]${NC} $timestamp - $line"
    elif echo "$line" | grep -q "googlevideo\|youtube"; then
        echo -e "${GREEN}[YOUTUBE]${NC} $timestamp - $line"
    elif echo "$line" | grep -q "doubleclick\|googlesyndication"; then
        echo -e "${YELLOW}[AUCTION]${NC} $timestamp - $line"
    fi
done

# Cleanup on exit
trap "kill $REDIS_PID 2>/dev/null" EXIT
