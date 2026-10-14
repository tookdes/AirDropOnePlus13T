# Stock RF backend assessment

Assessment date: **October 14, 2026**. Offline assessment complete; **real RF/AirDrop gate BLOCKED**.

## Scope and limits

The question is whether a supported bidirectional raw 802.11 backend can serve Wonder without replacing/unloading stock Wi-Fi, flashing, bypassing CRC/KCFI, or calling private functions through guessed addresses. Evidence combines captured stock ELF/BTF, exact pinned public sources, and earlier separately approved software-only observations. No phone operation was run during this offline assessment.

A missing symbol is not universal impossibility proof. An interface table is not firmware capability proof. Not every opaque vendor payload has been reverse-engineered. The conclusion is narrower: **no verified supported route is available from the examined interfaces under the stated constraints**.

## Capture identity and inventory

Derived module hashes, not proprietary binaries:

| Provider | SHA256 | Actual exported symbols |
| --- | --- | --- |
| `qca_cld3_peach_v2.ko` | `746c8459222670e7ffcbb30796c9032d59d60b6ac72f88ada435f8643a854dd2` | 0 |
| `cnss2.ko` | `2bddf5492bf827a1ff85352e8b57c2e836bcfeca4fcc8111acb2f119eaa46ac1` | 74 |
| `cfg80211.ko` | `e5c470d1cd3c7993788bfd05e7558b07ef3a0e05fd46c5cda22baf2930af7b87` | Independently captured provider metadata |

The target qcacld contains 18,468 defined functions. Having private monitor/adapter functions is not normal external-module callability: `hdd_open_adapter`/`hdd_start_adapter` are not exported, and the donor passthru registration/CNSS helper contracts are absent. No symbol/CRC/address workaround was implemented.

### Ordinary monitor TX gate

Captured kernel BTF gives `sizeof(net_device_ops)=704` and `ndo_start_xmit=0x20`. The same offset resolves station `hdd_hard_start_xmit`, providing a positive control. The selected 704-byte `wlan_mon_drv_ops` table contains only:

| Offset | Callback |
| --- | --- |
| `0x10` | `hdd_mon_open` |
| `0x18` | `hdd_stop` |
| `0xb8` | `hdd_get_stats` |

The TX slot contains neither nonzero unrelocated data nor an ELF callback relocation. This proves the ordinary compiled monitor netdev lacks a TX callback. It does not assert that every other packet-capture variant lacks TX.

### Vendor table decoding

`hdd_wiphy_vendor_commands` is 7,056 bytes: **126 records of 56 bytes**, not 48. The pinned common header includes `ANDROID_KABI_RESERVE(1)`. Every record's vendor ID, flags, padding/reserve, handler/policy pointers, relocation bounds, and duplicate IDs were checked. All IDs map to the exact vendor-subcommand enum, including OPLUS 1001-1003.

`VENDOR_CMD_RAW_DATA` is `(long)-ENODATA` (unsigned 64-bit value `2^64-61`), **not -1**. It tells cfg80211 to accept unparsed Netlink command data; it does not mean arbitrary over-the-air 802.11 transmission.

## Route matrix

| Route | Evidence and result | RF verdict |
| --- | --- | --- |
| Donor WonderTap external helper | Stock qcacld exports none; CNSS lacks the required Wonder provider entrypoint | Blocked for these modules |
| Ordinary stock monitor netdev | No TX callback; station positive control verified | Cannot be the complete TX/RX backend |
| Standard cfg80211 management TX | Captured binary checks frame type and returns `-EINVAL` for non-management frames when callbacks exist | Not raw data TX |
| Private `SENDACTIONFRAME` ioctl | Reviewed pinned code constructs a management/action header and invokes management TX | Not an arbitrary data-frame contract |
| `OFFLOADED_PACKETS` (79) | Association/local source MAC/nonzero period; prepends a 14-byte Ethernet header. Captured calls include association check and periodic-TX submission | Ethernet offload, not independent raw 802.11 injection |
| `WIFI_TEST_CONFIGURATION` (169) | Reviewed certification/generation settings and typed/nested attributes | No general raw-frame contract identified |
| NL80211 testmode / FTM | Captured callback calls FTM; pinned FTM branch rejects mission mode | Not an approved normal concurrent-Wi-Fi backend |
| `OEM_DATA` (182) | Actual host callback/SME/WMA edges; opaque bytes reach an OEM WMI command in pinned code | Firmware ABI and raw-frame behavior unproven |
| Capture controls (202/225) | RX/capture controls exist; concurrency restrictions and possible STA disconnect/P2P changes | Capture is not bidirectional RF proof |
| Ordinary station forwarding | Wonder's radiotap/raw-frame backend contract differs from Ethernet station TX | No pretend bridge or wlan0 RX-handler hijack |
| NAN_EXT (171), NDP (81), remaining vendor controls | Complete command inventory, not a complete proprietary-payload semantic audit | Not generic Wonder/raw-backend proof |

### Management binary guard

The captured `cfg80211_mlme_mgmt_tx` function starts at `.text+0x43454`. The audit fingerprints its entire prefix through the return path, including:

- `+0x40`: minimum frame length is 25.
- `+0x4c`: load frame control; `+0x50`: test mask `0x0c`.
- `+0x54`: branch to the management path only when the frame type is zero.
- `+0x58`: set return value `-22`; the verified return path follows.

Unavailable callbacks return `-95` before the frame check. Other builds/instruction sequences are rejected by the target-specific checker, not heuristically classified. The pinned `net/wireless/mlme.c:724-746` contract agrees with this captured binary check.

### Important positive capabilities and unknowns

- The stock **monitor-channel callback is present**, at cfg80211 ops offset `0x138`, resolving `wlan_hdd_cfg80211_set_mon_ch`. It checks regulatory state/BW and can change hardware mode. Its presence does not prove safe channel scheduling alongside station Wi-Fi or supply raw TX.
- `NAN_EXT` and `NDP` commands are registered. Legacy NAN enum ID **12 is not in this captured command table**. Header names alone are not runtime registrations.
- Reviewed local capture code requires exactly one active non-monitor adapter. RX-monitor creation has a branch that disconnects an active STA; packet-capture creation can delete/recreate P2P interfaces. Do not treat stock monitor creation as a harmless Wi-Fi-preserving experiment.
- Wonder prepares its private TX descriptor in headroom and submits a radiotap header plus an 802.11 frame to its physical backend. Sending that unchanged to the ordinary Ethernet station path does not implement the vendor contract.
- OEM payloads reach firmware, but no documented/verified generic raw TX command, compatible RX delivery, or safe channel/coexistence ABI was established. An opaque OEM gateway is an **unknown**, not a proof of impossibility and not permission to send guessed payloads.
- Both privately captured firmware images were hashed and searched statically. No Wonder/passthru literals were found, but strings cannot prove absent capabilities or identify the currently running image. No runtime firmware-service bitmap was captured by this assessment.

## Reproducible read-only inventory

The audit uses the standard-library-only parsers already in the repository. It never runs ADB, inserts a module, changes device state, rewrites module bytes/CRCs, or downloads firmware. Supply your privately captured files; the following PowerShell command uses placeholders and writes only an ignored JSON report:

```powershell
python tools/audit_rf_backend.py --qcacld PATH_TO_STOCK_QCACLD --cnss PATH_TO_STOCK_CNSS --stock-btf PATH_TO_STOCK_KERNEL_BTF --vendor-header PATH_TO_PINNED_QCA_VENDOR_H --cfg80211 PATH_TO_STOCK_CFG80211 --out .ci-logs/rf-interface-inventory.json
```

`--cfg80211` is optional; omitting it leaves the management guard unassessed. Its supplied binary must match the known captured guard, or extraction fails closed. Vendor-header mapping is provenance-labelled reference metadata, not firmware proof.

An exit code of **0 means successful inventory extraction only**. `radio_gate_passed` is always false. A missing monitor TX callback can establish absence for that table; a present callback is left **unproven** as raw TX. Output must be JSON and cannot overlap an input, including hardlinks. Malformed/ambiguous symbols, out-of-bounds/duplicate/unsupported relocations, wrong table stride, unexpected pointer/reserve bytes, and changed management guards are rejected.

Raw evidence, full source manifests, compiled handler/policy inventories, call-relocation inventories, firmware string reports, device logs, and the full route matrix remain in ignored local evidence directories. This document publishes only derived conclusions/metadata.

## Source provenance

The private source manifest records all 16 downloaded reference files and verifies their SHA256. Where an existing local vendor checkout used CRLF, content was compared after line-ending normalization; no persistent Git configuration was edited.

Pinned repositories/commits are listed in the root README. Principal public-source contracts:

- Common `include/net/cfg80211.h`: vendor-command layout/KABI reserve and RAW_DATA policy sentinel; `net/wireless/mlme.c`: management frame check.
- Target `vendor/qcom/opensource/wlan/qcacld-3.0/core/hdd/src/wlan_hdd_cfg80211.c`: offload builder, certification settings, testmode, capture and monitor-channel controls.
- Target `.../core/hdd/src/wlan_hdd_main.c`: monitor adapter/concurrency and netdev tables; `.../wlan_hdd_ioctl.c`: action-frame ioctl.
- Target `.../core/hdd/src/wlan_hdd_oemdata.c`, `.../core/sme/src/common/sme_api.c`, `.../core/wma/src/wma_features.c`, and host-common `wmi/src/wmi_unified_tlv.c`: OEM host-to-firmware path.
- Target `.../components/dp/core/src/wlan_dp_txrx.c`: monitor RX delivery; `vendor/oplus/kernel/wifi/wonder/mac80211.c`: Wonder backend packet contract.

Public source is not asserted to be byte-identical to every stock implementation. Compiled tables, exports, call relocations and the management guard are independently checked in captured binaries; source-only contracts remain qualified as such.

## Validation and safety disposition

- New self-contained audit tests: **19 passed**.
- Final LF-normalized local snapshot: **135 tests passed, zero skipped**, including the captured boot/BTF/export integration and actual shim C-body lifecycle mocks.
- Host mocks used existing Windows clang 19/MSVC facilities. Explicit host-only errno/Ethernet/byte-order compatibility headers were used; CRT builtin `offsetof` avoided a Windows macro's false UBSan null-reference diagnostic. Requested undefined-behavior checks remained enabled in trap-on-error mode. This is not Linux CI or target ABI validation.
- All test bodies/CRC expectations were preserved. Fixture generation used a per-process LF option only; no persistent Git setting changed and no module/CRC/firmware bytes were modified.
- The earlier `oplus_network_tuning` warning remains unresolved. Approximately three-minute software observations are not long-term stability or RF proof. The older reboot's cause remains unproven.

The offline phase is complete with a **blocked RF gate**, not a usable AirDrop package. Reopening requires a verified supported raw TX/RX contract, matching firmware/ABI evidence, and safe channel/coexistence behavior. Any subsequent state-changing device validation still needs explicit approval and a fresh read-only preflight. Nothing is automatically inserted, recreated, enabled, or packaged.
