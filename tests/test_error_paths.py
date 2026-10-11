"""Compile isolated source-extracted C fragments with host-side mocks.

These tests deliberately do not claim kernel-header, firmware or ABI coverage.
Both pristine donor behavior and the patched behavior are measured.
"""
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REL = Path('vendor/qcom/opensource/wlan/qcacld-3.0/core/hdd/src/wlan_hdd_wondertap.c')


def balanced_block(text, start):
    opening = text.index('{', start)
    depth = 0
    for pos in range(opening, len(text)):
        if text[pos] == '{':
            depth += 1
        elif text[pos] == '}':
            depth -= 1
            if depth == 0:
                return text[start:pos + 1]
    raise ValueError('Unbalanced source fragment')


def rate_function(text):
    start = text.index('static int\n__wlan_hdd_wondertap_set_fixed_tx_rate(')
    return balanced_block(text, start)


def mode_branch(text):
    start = text.index('if (hdd_get_conparam() != QDF_GLOBAL_MISSION_MODE)')
    return balanced_block(text, start)


PREAMBLE = r'''
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
typedef int WMI_RATE_PREAMBLE;
struct link { int vdev_id; };
struct hdd_adapter { struct link *deflink; };
typedef struct {
    int preamble;
    int bw;
    int gi;
    int nss;
    int mcs;
} qdf_wondertap_tx_rate_params_t;
enum { WONDERTAP_RATE_GI_DEFAULT, WONDERTAP_RATE_GI_SHORT,
       WONDERTAP_RATE_GI_0_8_US, WONDERTAP_RATE_GI_1_6_US,
       WONDERTAP_RATE_GI_3_2_US };
enum { wmi_vdev_param_fixed_rate, wmi_vdev_param_sgi, wmi_vdev_param_chwidth, VDEV_CMD };
#define hdd_err(...) ((void)0)
static int calls;
static int errors[3];
static int observed[3];
static WMI_RATE_PREAMBLE wlan_hdd_convert_wonder_preamble_to_wmi(int p) { return p; }
static uint32_t hdd_assemble_rate_code(int p, int n, int m) { return (uint32_t)(p+n+m); }
static int wma_cli_set_command(int id, int param, int value, int cmd) {
    (void)id; (void)cmd;
    observed[param] = value;
    return errors[calls++];
}
#define QDF_GLOBAL_MISSION_MODE 0
static int current_mode;
static int hdd_get_conparam(void) { return current_mode; }
'''

MAIN = r'''
int main(void) {
    struct link link = {7};
    struct hdd_adapter adapter = {&link};
    qdf_wondertap_tx_rate_params_t p = {1, 2, WONDERTAP_RATE_GI_SHORT, 1, 3};
    const int failures[4][3] = {{0,0,0}, {-5,0,0}, {0,-6,0}, {0,0,-7}};
    int i, j;
    for (i=0;i<4;i++) {
        int ret;
        calls=0;
        for(j=0;j<3;j++) errors[j]=failures[i][j];
        ret=__wlan_hdd_wondertap_set_fixed_tx_rate(&adapter, &p);
        printf("rate %d %d %d\n", i, ret, calls);
    }
    for(i=0;i<2;i++) {
        current_mode=i;
        printf("mode %d %d\n", i, isolated_mode_branch());
    }
    for(i=0;i<5;i++) {
        int ret;
        p.gi=i;
        calls=0;
        for(j=0;j<3;j++) errors[j]=0;
        ret=__wlan_hdd_wondertap_set_fixed_tx_rate(&adapter, &p);
        printf("gi %d %d %d\n", i, ret, observed[wmi_vdev_param_sgi]);
    }
    return 0;
}
'''


def run_mock(source):
    branch = '\nstatic int isolated_mode_branch(void) {\nint result = 0;\n' + mode_branch(source).replace('errno', 'result') + '\ndestroy_sync:\nreturn result;\n}\n'
    program = PREAMBLE + rate_function(source) + branch + MAIN
    with tempfile.TemporaryDirectory() as td:
        path = Path(td)
        c, binary = path / 'mock.c', path / 'mock'
        c.write_text(program)
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', str(c), '-o', str(binary)], check=True, capture_output=True)
        return subprocess.check_output([str(binary)], text=True)


class ErrorPropagationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.donor = run_mock((ROOT / 'upstream/op15-excerpts' / REL).read_text())
        cls.patched = run_mock((ROOT / 'module/staged-source' / REL).read_text())
        cls.record = {'scope': 'Host C mocks of source-extracted rate helper and non-mission branch; NOT kernel module build',
                      'pristine_donor_stdout': cls.donor, 'patched_stdout': cls.patched}
        (ROOT / 'evidence/host-c-regression.json').write_text(json.dumps(cls.record, indent=2) + '\n')

    def test_pristine_exhibits_swallowed_errors(self):
        self.assertIn('rate 1 0 3', self.donor)
        self.assertIn('rate 2 0 3', self.donor)
        self.assertIn('mode 1 0', self.donor)

    def test_patched_rate_failures_stop_immediately(self):
        for line in ('rate 0 0 3', 'rate 1 -5 1', 'rate 2 -6 2', 'rate 3 -7 3'):
            self.assertIn(line, self.patched)

    def test_patched_mode_rejects_non_mission(self):
        self.assertIn('mode 0 0', self.patched)
        mode_ret = int(re.search(r'^mode 1 (-?\d+)$', self.patched, re.M).group(1))
        self.assertLess(mode_ret, 0)

    def test_gi_mapping_preserved(self):
        expected = [0, 1, 0, 2, 3]
        for i, value in enumerate(expected):
            self.assertIn(f'gi {i} 0 {value}', self.donor)
            self.assertIn(f'gi {i} 0 {value}', self.patched)


if __name__ == '__main__':
    unittest.main(verbosity=2)
