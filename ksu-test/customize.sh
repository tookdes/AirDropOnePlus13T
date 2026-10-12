#!/system/bin/sh
# Fail closed: the zip is incomplete unless Stage A verified both ARM64 probes.
ui_print "OP13T Stage A ABI probe (NOT AirDrop)"

MISSING=""
for f in hello_13t.ko wonder_shim_13t.ko SHA256SUMS stage-a-result.json; do
  if [ ! -f "$MODPATH/$f" ]; then
    MISSING="$MISSING $f"
  fi
done
if [ -n "$MISSING" ]; then
  ui_print "Incomplete package, missing:$MISSING"
  ui_print "This zip is assembled only after GitHub Actions Stage A ABI gates pass."
  abort "Refusing to install an incomplete probe package"
fi

if ! grep -q '"build_and_offline_abi_gates_passed": true' "$MODPATH/stage-a-result.json"; then
  abort "Stage A ABI gates did not pass; refusing install"
fi
if grep -q '"airdrop_available": true' "$MODPATH/stage-a-result.json"; then
  abort "Refusing a package that claims AirDrop availability"
fi

# Default is diagnostics-only. Full shim (DT mutation) requires an explicit file.
if [ ! -f "$MODPATH/enable-full-shim" ]; then
  touch "$MODPATH/diagnostics_only"
fi

ui_print "Installed probe files only. After reboot:"
ui_print "  insmod hello_13t.ko"
ui_print "  insmod wonder_shim_13t.ko diagnostics_only=1"
ui_print "Do not unload Wi-Fi. Do not replace qca_cld3."
