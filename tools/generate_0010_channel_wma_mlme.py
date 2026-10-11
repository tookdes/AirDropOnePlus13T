#!/usr/bin/env python3
"""Generate the reviewed passthru channel/WMA/MLME control patch.

Four donor-introduction files are imported. An unrelated WPA2 PMKID fix that
shares the PE source file is explicitly removed before the patch is emitted.
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
EXPECTED = "bd145ca474181e93ca5416a6525ef4281640859e5a841ec8f39b420a2483a064"
PATHS = [
    "vendor/qcom/opensource/wlan/qcacld-3.0/core/mac/src/pe/lim/lim_process_sme_req_messages.c",
    "vendor/qcom/opensource/wlan/qcacld-3.0/core/wma/src/wma_dev_if.c",
    "vendor/qcom/opensource/wlan/qcacld-3.0/components/mlme/core/src/wlan_mlme_vdev_mgr_interface.c",
    "vendor/qcom/opensource/wlan/qca-wifi-host-cmn/umac/mlme/include/wlan_vdev_mlme.h",
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


def strip_unrelated_pmksa(work: Path) -> None:
    p = work / PATHS[0]
    s = p.read_text()
    old = "\tstruct bss_description *bss_desc;\n\tint32_t akm;\n"
    if s.count(old) != 1:
        raise ValueError("PMKID declaration drift")
    s = s.replace(old, "\tstruct bss_description *bss_desc;\n", 1)

    old = (
        "\takm = wlan_crypto_get_param(session->vdev,\n"
        "\t\t\t\t    WLAN_CRYPTO_PARAM_KEY_MGMT);\n"
        "\tif (pmksa_peer && WLAN_CRYPTO_IS_WPA2(akm)) {\n"
        "\t\tpe_debug(\"WPA2 does not support PMKID, clearing PMKID for AKM %d\",\n"
        "\t\t\t akm);\n"
        "\t\tqdf_mem_zero(pmksa_peer->pmkid, sizeof(pmksa_peer->pmkid));\n"
        "\t}\n\n"
    )
    if s.count(old) != 1:
        raise ValueError("PMKID block drift")
    p.write_text(s.replace(old, "", 1))


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
        raise SystemExit("0010 donor scope drift")

    with tempfile.TemporaryDirectory() as td:
        work = Path(td) / "work"
        run(["git", "-C", str(args.target), "worktree", "add",
             "--detach", str(work), TARGET])
        try:
            run(["git", "apply", "--check", "-"], cwd=work,
                input_data=introduction)
            run(["git", "apply", "-"], cwd=work, input_data=introduction)
            strip_unrelated_pmksa(work)
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
        raise SystemExit(f"0010 output drift: {digest} != {EXPECTED}")
    if patch.count(b"diff --git a/") != len(PATHS):
        raise SystemExit("0010 must touch exactly four control-path files")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(patch)
    print(f"{args.out} sha256={digest} bytes={len(patch)}")


if __name__ == "__main__":
    main()
