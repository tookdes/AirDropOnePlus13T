#!/system/bin/sh
MODDIR="${0%/*}"
# Do not autoload. The operator must insmod after confirming dmesg/kmsg.
# Keep a marker so it is obvious this is a probe, not AirDrop.
[ -f "$MODDIR/NOT_AIRDROP" ] || exit 0
exit 0
