# AirDropOnePlus13T

Source-based WonderTap backport for OnePlus 13T (PJD110 / OP612BL1), targeting the captured Android 16 ROM and stock Android 15-6.6.89 kernel.

**Development in progress. No working AirDrop installer has been released.** A successful source download, compilation, or CRC check does not prove live-device compatibility.

## Target and immutable source references

- Target kernel: `6.6.89-android15-8-g5a0ffb447c1d-ab13771415-4k`
- Kernel common: `OnePlusOSS/android_kernel_common_oneplus_sm8750` at `5a0ffb447c1dbd82e8e3af7a98c4a629f4b6d143`
- Target vendor modules: `OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_sm8750` at `6a196f79f77acd55cf302e1696c038e4cad99254`
- Donor vendor modules: `OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_sm8850` at `5ab2a689ff87d7d28c511f1762cf41c1b90d965a`
- Toolchain: Android clang r510928, build 11368308; compiler identity must be checked before use.

## Safety boundary

Original boot images, proprietary firmware, factory calibration data, device logs, credentials, and user files are not published here. Public-source build artifacts are not firmware payloads. No workflow connects to a phone, flashes partitions, unloads Wi-Fi drivers, or bypasses MODVERSIONS/KCFI.

Stock GNG.1.0 firmware is not approved for passthru bring-up. The final runtime-only KernelSU package remains gated on target ABI validation, a compatible firmware set, driver/framework integration, and explicit on-device bring-up and rollback tests.

## Build infrastructure

The source-bundle workflow retrieves pinned public sources and the compiler into GitHub Actions artifacts. This also allows offline compilation against the private captured stock evidence without uploading that evidence. Individual bundles have SHA256 manifests and recorded git revisions.

Existing reviewed patches, regression tests, the provider shim, and Stage A build tools are being imported into this repository.
