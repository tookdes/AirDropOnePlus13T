#!/usr/bin/env python3
"""Generate the reviewed 13T MAC/SME WonderTap session-control patch.

The Qualcomm donor introduction is applied only to twelve pinned files. Three
13T monitor-mode public APIs are preserved as compatibility wrappers so the
WonderTap backport does not silently break the existing monitor path.
"""
from __future__ import annotations
import argparse
import hashlib
import subprocess
import tempfile
from pathlib import Path

TARGET = "6a196f79f77acd55cf302e1696c038e4cad99254"
INTRO = "307d23721d20e21b8160b9ba9c3cb50911ff8c00"
PARENT = "7fb7abf097a18c6e2ad2fb9d18876b095898e87f"
EXPECTED = "b7e69e63f3375fb4ad02f958fd4926a441c652a6bedd547fe50095b5e3c6af25"
PATHS = [
    "vendor/qcom/opensource/wlan/qcacld-3.0/core/mac/inc/sir_api.h",
    "vendor/qcom/opensource/wlan/qcacld-3.0/core/mac/inc/wni_api.h",
    "vendor/qcom/opensource/wlan/qcacld-3.0/core/mac/src/pe/include/lim_global.h",
    "vendor/qcom/opensource/wlan/qcacld-3.0/core/mac/src/pe/lim/lim_process_message_queue.c",
    "vendor/qcom/opensource/wlan/qcacld-3.0/core/mac/src/pe/lim/lim_process_mlm_rsp_messages.c",
    "vendor/qcom/opensource/wlan/qcacld-3.0/core/mac/src/pe/lim/lim_session.c",
    "vendor/qcom/opensource/wlan/qcacld-3.0/core/mac/src/pe/lim/lim_utils.c",
    "vendor/qcom/opensource/wlan/qcacld-3.0/core/mac/src/sys/legacy/src/utils/src/mac_trace.c",
    "vendor/qcom/opensource/wlan/qcacld-3.0/core/sme/inc/sme_api.h",
    "vendor/qcom/opensource/wlan/qcacld-3.0/core/sme/inc/sme_internal.h",
    "vendor/qcom/opensource/wlan/qcacld-3.0/core/sme/src/common/sme_api.c",
    "vendor/qcom/opensource/wlan/qcacld-3.0/core/sme/src/csr/csr_api_roam.c",
]


def run(args, cwd=None, input_data=None) -> bytes:
    cp = subprocess.run(
        args, cwd=cwd, input=input_data, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if cp.returncode:
        raise RuntimeError(
            "command failed: " + " ".join(map(str, args)) + "\n" +
            cp.stderr.decode(errors="replace")[:2000]
        )
    return cp.stdout


def once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise ValueError(f"{label}: expected one exact anchor, got {count}")
    return text.replace(old, new, 1)


def add_13t_compatibility(work: Path) -> None:
    # Do not import an unrelated donor copyright synchronization.
    p = work / PATHS[7]
    s = p.read_text()
    s = once(
        s,
        " * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.\n",
        " * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.\n",
        "mac_trace copyright",
    )
    p.write_text(s)

    # Keep the 13T monitor public ABI while adding the donor generalized APIs.
    p = work / PATHS[8]
    s = p.read_text()
    s = once(
        s,
        "QDF_STATUS sme_create_pe_session(mac_handle_t mac_handle, uint8_t *bssid,\n"
        "\t\t\t\t uint8_t vdev_id, enum QDF_OPMODE op_mode);\n",
        "QDF_STATUS sme_create_pe_session(mac_handle_t mac_handle, uint8_t *bssid,\n"
        "\t\t\t\t uint8_t vdev_id, enum QDF_OPMODE op_mode);\n"
        "QDF_STATUS sme_create_mon_session(mac_handle_t mac_handle, uint8_t *bssid,\n"
        "\t\t\t\t  uint8_t vdev_id);\n",
        "create prototype",
    )
    s = once(
        s,
        "QDF_STATUS sme_delete_pe_session(mac_handle_t mac_handle, uint8_t vdev_id,\n"
        "\t\t\t\t enum QDF_OPMODE op_mode);\n",
        "QDF_STATUS sme_delete_pe_session(mac_handle_t mac_handle, uint8_t vdev_id,\n"
        "\t\t\t\t enum QDF_OPMODE op_mode);\n"
        "QDF_STATUS sme_delete_mon_session(mac_handle_t mac_handle, uint8_t vdev_id);\n",
        "delete prototype",
    )
    s = once(
        s,
        "QDF_STATUS sme_set_op_mode_cb(mac_handle_t mac_handle,\n"
        "\t\t\t      void (*monitor_mode_cb)(uint8_t vdev_id,\n"
        "\t\t\t\t\t\t      bool is_up),\n"
        "\t\t\t      void (*passthrough_mode_cb)(uint8_t vdev_id,\n"
        "\t\t\t\t\t\t\t  bool is_up));\n",
        "QDF_STATUS sme_set_op_mode_cb(mac_handle_t mac_handle,\n"
        "\t\t\t      void (*monitor_mode_cb)(uint8_t vdev_id,\n"
        "\t\t\t\t\t\t      bool is_up),\n"
        "\t\t\t      void (*passthrough_mode_cb)(uint8_t vdev_id,\n"
        "\t\t\t\t\t\t\t  bool is_up));\n"
        "QDF_STATUS sme_set_monitor_mode_cb(mac_handle_t mac_handle,\n"
        "\t\t\t\t   void (*monitor_mode_cb)(uint8_t vdev_id,\n"
        "\t\t\t\t\t\t\t   bool is_up));\n",
        "callback prototype",
    )
    p.write_text(s)

    p = work / PATHS[10]
    s = p.read_text()
    old = "void sme_set_monitor_mode_cb(struct mac_context *mac,"
    if s.count(old) != 2:
        raise ValueError(f"local monitor callback helper count={s.count(old)}")
    s = s.replace(old, "void sme_store_monitor_mode_cb(struct mac_context *mac,")
    s = once(
        s,
        "\tsme_set_monitor_mode_cb(mac, monitor_mode_cb);",
        "\tsme_store_monitor_mode_cb(mac, monitor_mode_cb);",
        "helper call",
    )
    s = once(
        s,
        "\treturn status;\n}\n\n"
        "QDF_STATUS sme_delete_pe_session(mac_handle_t mac_handle, uint8_t vdev_id,\n",
        "\treturn status;\n}\n\n"
        "QDF_STATUS sme_create_mon_session(mac_handle_t mac_handle, uint8_t *bss_id,\n"
        "\t\t\t\t  uint8_t vdev_id)\n"
        "{\n"
        "\treturn sme_create_pe_session(mac_handle, bss_id, vdev_id,\n"
        "\t\t\t\t     QDF_MONITOR_MODE);\n"
        "}\n\n"
        "QDF_STATUS sme_delete_pe_session(mac_handle_t mac_handle, uint8_t vdev_id,\n",
        "create wrapper",
    )
    s = once(
        s,
        "\treturn status;\n}\n\n"
        "void\nsme_set_del_peers_ind_callback(mac_handle_t mac_handle,\n",
        "\treturn status;\n}\n\n"
        "QDF_STATUS sme_delete_mon_session(mac_handle_t mac_handle, uint8_t vdev_id)\n"
        "{\n"
        "\treturn sme_delete_pe_session(mac_handle, vdev_id, QDF_MONITOR_MODE);\n"
        "}\n\n"
        "void\nsme_set_del_peers_ind_callback(mac_handle_t mac_handle,\n",
        "delete wrapper",
    )
    s = once(
        s,
        "\treturn qdf_status;\n}\n\n"
        "QDF_STATUS sme_process_monitor_mode_vdev_evt(uint8_t vdev_id, bool is_up)\n",
        "\treturn qdf_status;\n}\n\n"
        "QDF_STATUS sme_set_monitor_mode_cb(mac_handle_t mac_handle,\n"
        "\t\t\t\t   void (*monitor_mode_cb)(uint8_t vdev_id,\n"
        "\t\t\t\t\t\t   bool is_up))\n"
        "{\n"
        "\treturn sme_set_op_mode_cb(mac_handle, monitor_mode_cb, NULL);\n"
        "}\n\n"
        "QDF_STATUS sme_process_monitor_mode_vdev_evt(uint8_t vdev_id, bool is_up)\n",
        "callback wrapper",
    )
    p.write_text(s)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--donor", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    head = run(["git", "-C", str(args.target), "rev-parse", "HEAD"]).decode().strip()
    if head != TARGET:
        raise SystemExit(f"wrong target commit: {head}")
    for commit in (PARENT, INTRO):
        run(["git", "-C", str(args.donor), "cat-file", "-e", commit + "^{commit}"])

    introduction = run([
        "git", "-C", str(args.donor), "diff", "--binary",
        PARENT, INTRO, "--", *PATHS
    ])
    if introduction.count(b"diff --git a/") != len(PATHS):
        raise SystemExit("donor introduction scope drift")

    with tempfile.TemporaryDirectory() as td:
        work = Path(td) / "work"
        run(["git", "-C", str(args.target), "worktree", "add",
             "--detach", str(work), TARGET])
        try:
            run(["git", "apply", "--check", "-"], cwd=work,
                input_data=introduction)
            run(["git", "apply", "-"], cwd=work, input_data=introduction)
            add_13t_compatibility(work)
            run(["git", "diff", "--check"], cwd=work)
            patch = run(["git", "diff", "--binary", "--full-index"], cwd=work)
        finally:
            subprocess.run(
                ["git", "-C", str(args.target), "worktree", "remove",
                 "--force", str(work)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

    digest = hashlib.sha256(patch).hexdigest()
    if digest != EXPECTED:
        raise SystemExit(f"0009 output drift: {digest} != {EXPECTED}")
    if patch.count(b"diff --git a/") != len(PATHS):
        raise SystemExit("0009 must touch exactly twelve MAC/SME files")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(patch)
    print(f"{args.out} sha256={digest} bytes={len(patch)}")


if __name__ == "__main__":
    main()
