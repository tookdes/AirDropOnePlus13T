# AirDropOnePlus13T

Source-based WonderTap backport for OnePlus 13T (PJD110 / OP612BL1), targeting the captured Android 16 ROM and stock Android 15-6.6.89 kernel.

**No working AirDrop installer has been released.** The software-only Wonder path has been exercised manually, but the real radio backend is **BLOCKED** under the unchanged-stock-Wi-Fi-driver constraints. Compilation, CRC agreement, registration, and interface UP are separate gates; none proves AirDrop.

## Target and immutable source references

- Target kernel: `6.6.89-android15-8-g5a0ffb447c1d-ab13771415-4k`
- Kernel common: `OnePlusOSS/android_kernel_common_oneplus_sm8750` at `5a0ffb447c1dbd82e8e3af7a98c4a629f4b6d143`
- Target vendor modules: `OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_sm8750` at `6a196f79f77acd55cf302e1696c038e4cad99254`
- Donor vendor modules: `OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_sm8850` at `5ab2a689ff87d7d28c511f1762cf41c1b90d965a`
- Kernel toolchain: Android clang r510928, build 11368308; compiler identity must be checked before use.

## Safety boundary

The following is the **current device-testing gate**, not a declaration that the
source-backport architecture is abandoned. The read-only RF assessment below
tests routes available while the shipping Wi-Fi stack is left unchanged. The
separate patched-qcacld + compatible-firmware route remains an unfinished
engineering path and is not approved for device bring-up yet.

- Do not currently replace/unload stock `qca_cld3`, `cfg80211`, or `mac80211`, or flash partitions, until the patched-driver module/ABI closure, matching firmware set, and rollback preflight are complete.
- Any module operation, interface creation/UP/DOWN/deletion, DT edit, capture enablement, channel change, or firmware command requires explicit stage-specific approval and a fresh read-only preflight.
- Never use `physical_name=wlan0`: Wonder would register an RX handler on stock Wi-Fi and can disrupt connectivity.
- Never patch module CRCs/vermagic/KCFI, call private functions by guessed address, or package candidate wireless modules in a KernelSU installer.
- Original boot images, firmware/calibration blobs, device logs, credentials, and user files stay private and ignored. Public-source build artifacts are not firmware payloads.
- Public CI has no phone connection or device bring-up steps. No workflow bypasses MODVERSIONS/KCFI.

## Verified compile/ABI candidate

The tested Wonder build came from wireless CI run **38342996908**, source commit `61db8f1b6c7d4b56f05bce29fb0c7bf4062c4b5f`:

- Stock `cfg80211.ko` **and** `mac80211.ko` were captured and confirmed loaded. A built-in boot-config setting alone does not describe the vendor module stack.
- Required Wonder header configuration: `CONFIG_PM=y`, `CONFIG_MAC80211_DEBUGFS=n`, `CONFIG_NL80211_TESTMODE=y`.
- Callback-slot checks place `wake_tx_queue` at `0x2f0`; disabling DEBUGFS alone was insufficient. The missing testmode cmd/dump slots also mattered. `start`/`config` were not shifted by that error.
- All **69 strong Wonder imports** have CRC records, plus `module_layout` (70 records total), checked against actual captured providers. Core CRCs are independently regenerated, not copied into a module to bypass checks.
- `ieee80211_alloc_hw_nm` CRC is `0xa9cce254`; `module_layout` is `0x4e276f37`.
- The 26 initialized mac80211 callbacks and the inspected layout/KCFI callsites passed their bounded checks. This is not complete ABI or RF certification.

## Manual device observations through October 14, 2026

These are local, separately approved tests, **not public CI results**:

| Stage | Observation | What it does not establish |
| --- | --- | --- |
| Stage A diagnostic probes | Both probes could be inserted | No radio implementation |
| Wonder-only insertion | Approximately 182 seconds observed without a new severe log or reboot | No interface/RF use |
| Software shim registration | Approximately 184 seconds; Wonder wiphy registered and vendor binding succeeded | Stub has no radio passthrough |
| Software monitor UP | Approximately 183 seconds; interface UP, RX/TX counters zero | Not on-air TX/RX or long-term stability |
| Monitor DOWN | A new stock `oplus_network_tuning` softirq WARNING was captured; cleanup stopped before deletion | Warning remains unresolved; does not prove the older reboot cause |
| Renewed approval: delete already-DOWN monitor | Approximately 123 seconds; interface absent, same boot, stock Wi-Fi stayed UP | No module/DT teardown |

At the last recorded post-cleanup snapshot, `wlan1` was absent but Wonder, the software shim, and the temporary DT provider property remained. This is a historical snapshot, not a current preflight. Do not reload modules or recreate a monitor automatically.

## Completed offline RF assessment

The captured stock module inventory and pinned-source route analysis found:

- Ordinary monitor `net_device_ops` has **no `ndo_start_xmit`**; station TX is a positive control at the same stock-BTF offset.
- Standard management TX rejects non-management frame types in the captured cfg80211 binary.
- Packet offload constructs Ethernet frames; FTM requires a factory/test operating mode; capture/RX and monitor-channel support do not supply missing raw data TX.
- All **126 compiled vendor commands** were decoded, including their handlers/policies; zero command IDs remain unmapped.
- OEM firmware commands remain **unproven opaque protocols**, not a validated injection backend. Static firmware strings are not capability proof.

**Conclusion:** no supported bidirectional raw 802.11 backend has been verified for these captured interfaces while keeping the stock driver unchanged. This does not prove every conceivable firmware path impossible. There is no justification to repeat software-monitor UP tests or ship a pretend radio bridge.

**Scope of that conclusion:** it closes the unchanged-stock-driver shortcut, not
the original OnePlus 15 → 13T passthru backport. The latter still requires a
completed/loadable patched qcacld, the Wonder provider/shim contract, a verified
compatible GNG.2.0 firmware set, and an explicit rollback-guarded Stage-D
preflight before any state-changing phone test.

See [the RF route assessment](docs/rf-backend-status.md) for the evidence scope, reproducible read-only audit, unknowns, and requirements for reopening the RF gate.

## Build infrastructure and testing

Pinned public-source bundles, ten reviewed seed vendor patches, four Wonder smoke patches, regression tests, the provider shim, and CRC/layout tools are included.

Strict qcacld run **38592818084** at `84284b8` passed compilation and provider-backed modpost on October 15, 2026 (Singapore): `module_completion_gate=PASSED_OFFLINE`. The 566/570 baseline/candidate raw undefined ELF symbols are normal module imports, **not unresolved modpost errors**. Candidate-only imports are `dev_open`, `dev_close`, `get_random_u32`, and the real `wonder_shim_13t` export `cnss_set_vendor_wonder_priv_data`.

The stock consumer's **588 version records now all have actual captured-provider export crosschecks**. The additional 56 were checked against nine provider binaries, including two extracted privately from a read-only capture of the active vendor boot ramdisk. Only derived ABI metadata/hashes are included here; no private images, modules, or capture paths. CRC evidence does not prove loaded-memory identity, shared struct layouts, KCFI compatibility, or loadability.

**The strict candidate is still diagnostic:** it combines the ten seed patches with **44 file-wide donor sync paths**, including unrelated changes. It is not an audited/minimal production patch series. Firmware compatibility, real provider binding and on-air bidirectional RF remain unproven. **Do not insert this candidate.** The new artifact-freeze tool archives the same-build shim, complete kernel config, checked provider tables and final-ELF metadata, rather than silently substituting an older shim. Debug-stripped diagnostic derivatives, when produced, are separately hashed and must preserve all allocated bytes/imports/versions; raw originals are retained.

The optional Stage A KernelSU archive is a **probe-only file staging package**, not AirDrop. It does not autoload the probes. Wireless smoke outputs are diagnostics, not replacements for the loaded stock providers.

The offline assessment adds `tools/audit_rf_backend.py` and 19 self-contained tests. The final local LF-normalized regression snapshot ran **135 tests, all passing, zero skipped**, including private stock integration. Host C mocks used existing Windows clang/MSVC facilities with enforcing UBSan traps and explicit compatibility headers; this is not a new Linux CI run or a fresh target-kernel build. No persistent Git configuration or target module bytes were changed.
