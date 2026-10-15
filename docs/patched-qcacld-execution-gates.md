# Patched qcacld execution gates (October 15, 2026)

The main route is **patched 13T qcacld + WonderTap + hardware-matched GNG.2.0 firmware + runtime shim**. The unchanged-stock-driver RF shortcut is a separate closed investigation, not a verdict that this project has failed.

## Completed evidence and remaining boundaries

- Strict run `38592818084` at `84284b8` passed compilation/provider-backed modpost. Raw undefined symbol counts 566/570 represent imports, not 566/570 unresolved modpost errors.
- All **588 stock consumer CRC records** now match **actual captured provider exports**. The last 56 were independently checked against nine module binaries. Two unavailable as mounted module files were extracted privately from the active vendor boot ramdisk. Only derived symbol/provider/hash metadata is committed.
- `PASSED_OFFLINE` is a **metadata/build** gate. It does not certify shared layouts, callback prototypes/KCFI, loadability, firmware, RF or AirDrop.
- The strict CLI now fails when its provider gate fails even if compilation succeeds. Missing/conflicting fresh core CRCs, missing providers, a misidentified shim, unversioned imports and incorrect dependencies have enforcing negative tests.
- The artifact-freeze step retains the same-build shim, full common-kernel configuration/autoconf, provider tables, source/compiler identities, logs and raw final modules. A separately hashed debug-stripped derivative must preserve all allocated section bytes, import symbols, version records and modinfo. This is **not** CRC/vermagic/KCFI patching, a release, or a KernelSU package.
- A new cfg80211 callback audit compares actual ELF relocation slots with the captured stock table (65 initialized callbacks, 1032 bytes). Stock is the positive control. Header configuration and provider CRC closure must not be mistaken for identical callback layouts.

## New final-ELF findings (not just compiler results)

Run `38699838731` at `3c8813c` again passed compilation and strict provider modpost, but the new final-ELF gate **correctly failed**: its baseline/candidate emitted **1044/1045 exports**, whereas captured stock qcacld exports none. The same-build audit archive was recovered with a verified ZIP digest; its debug-stripped modules preserve raw allocated bytes/imports/CRCs.

The local ELF callback audit then proved a second, safety-critical mismatch in **both** rebuilt modules: `cfg80211_ops` was **1016 bytes instead of stock 1032**, and **32 initialized callbacks after the testmode slots were 0x10 bytes early**. For example, management TX was at `0x1f8` instead of stock `0x208`. This is a concrete reason not to load the strict-modpost artifact, not a hypothetical concern and not an explanation of the earlier device reboot.

The corrective build selects the vendor **`CONFIG_NL80211_TESTMODE=y` Kbuild branch and `CONFIG_NL80211_TESTMODE=1` header macro together**, confined to qcacld compilation. It also selects the existing QDF **`CONFIG_WLAN_DISABLE_EXPORT_SYMBOL=y`** policy, with source-contract checks. No stock boot config or module CRC bytes are rewritten. Complete common configuration **and actual module compile commands** are archived so the vendor header overrides are not hidden.

These corrections must pass a **new** build, zero-export check and compiled callback-slot gate. The previous `PASSED_OFFLINE` provider result remains valid only within its narrower scope. Fresh kernel CRC generation still uses the original validated common-kernel configuration.

## Source minimization

The broad compile candidate is **ten reviewed seed patches plus 44 file-wide donor paths**, not just ten patches.

The initial target-specific minimization profile inventories **196 extra hunks** and keeps **40 paths / 182 hunks**. It removes:

1. The unrelated zero-PMKID crypto behavior change (preserve pinned target behavior).
2. Donor-board `canoe-peach-cnss.dtsi` nodes (not a 13T DT deployment plan).
3. Kiwi and QCC2072 HAL registration changes (retain target Peach/common padding support).
4. Six standalone copyright-only hunks.

Every retained path/hunk is byte-pinned and has a grouped dependency rationale. Policy tables have many repeated passthru entries; they cannot be discarded just because they account for a large part of the diff. This is an **initial grouped source review**, not a completed production review or runtime approval. The broad candidate remains reproducible separately.

The minimized tree was reproduced locally from the exact target commit with LF-normalized seed patches. Its four excluded files match the target baseline; the new compile regression must be reported separately from the already-passed broad build. Ordinary Wi-Fi behavior, raw-buffer lengths/headroom/ownership and concurrent teardown still need bounded code/ABI checks before any runtime approval.

A local reproduction issue was also fixed: when a disposable tree is nested below another Git repository, `git apply` can return success while skipping paths outside that repository subdirectory. The generator now sets an explicit per-process repository-discovery ceiling. A regression verifies that patches actually change the intended nested output. No persistent user Git configuration changes are needed.

## Firmware gate: precisely blocked, not bypassed

Read-only target observations on October 15 show a CNSS PCI endpoint **17CB:110E**, subsystem **17CB:110E**, PCI revision **0x01**. PCI revision is not proof of firmware silicon/board compatibility, and marketing/model strings are not substitutes for these checks.

The only privately captured firmware binaries currently inventoried identify as **GNG.1.0-03342**, with `7880.wlanfw.eval_v1_TOQ` / `eval_v2_TOQ` variants. They are not approved for passthru tests. Missing Wonder/passthru strings do not prove missing firmware capabilities or identify the image currently running.

**No hardware-matched GNG.2.0 binary set with verified official-package provenance has been established.** A bounded public code search did not supply one; this is not an exhaustive OTA survey or proof that no such firmware exists.

Before any candidate can advance, privately record:

- Official donor/package URL and identity, image-component manifest, hashes and provenance.
- Chip/PCI ID, hardware and firmware silicon revision compatibility; do not equate a family string with compatibility.
- Board-data/calibration requirements and the complete image set selected by the driver. Preserve the target's own BDF/NV/calibration; never transplant unrelated donor NV.
- WMI/HTT/passthru ABI/service evidence matching the imported source, plus the limits of static evidence.
- A restore path for the **original driver and original firmware**. Source compatibility or a GNG.2.0 string cannot replace this evidence.

There are no guessed firmware commands, download/install workarounds, CRC rewrites, partition writes or firmware substitutions in this stage.

## Future runtime preflight (requires separate approval)

1. Establish an independent USB/control connection first. The currently observed transport is Wi-Fi ADB; it cannot be the sole recovery/control path during Wi-Fi replacement. Do not change USB/developer settings automatically.
2. Capture current boot ID, uptime, loaded modules, parameters, provider property/bindings and baseline warnings. The software shim and temporary DT property may still be present; a real backend must use `software_ops=0` and must not race an existing component binding.
3. Document the stock restore/reboot procedure and actual dependency/loading order. No force unload, partition flashing or `physical_name=wlan0`.
4. Obtain **new, operation-specific approval** before any driver/firmware switch, module unload/load, DT/interface changes or reboot. This document authorizes none of them.
5. After approval only: patched ordinary-Wi-Fi baseline, real provider binding, independent over-air bidirectional raw TX/RX/channel evidence, then AWDL and end-to-end AirDrop with file hashes.
6. Stop on a new WARNING/Oops/CFI/firmware SSR. The earlier `oplus_network_tuning` timer warning remains unresolved. Counters, successful registration, a connected log and software TX status are not RF proof.
