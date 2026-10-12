#!/system/bin/sh
# Intentionally empty. Probes are loaded manually after boot so a bad module
# cannot brick early boot. KernelSU still records the module as installed.
exit 0
