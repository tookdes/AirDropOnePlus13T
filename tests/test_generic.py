"""Execute actual generic Wonder C with mock kernel services and the real API header."""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
REL = 'vendor/oplus/kernel/wifi/wonder/wondertap.c'
HEADER = ROOT/'upstream/op13t-excerpts/vendor/oplus/kernel/wifi/wonder/include/wonder/wondertap.h'
PRE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define BIT(n) (1U << (n))
#include "API_HEADER"
#define wonder_error(...) ((void)0)
#define wonder_warn(...) ((void)0)
#define wonder_info(...) ((void)0)
struct mutex { int held; };
static void mutex_lock(struct mutex *m) { assert(!m->held); m->held = 1; }
static void mutex_unlock(struct mutex *m) { assert(m->held); m->held = 0; }
static unsigned int sleeps;
static void msleep(unsigned int ms) { assert(ms==400); sleeps++; }
static void eth_random_addr(u8 *mac) { memset(mac, 0x12, 6); }
enum { WONDERTAP_STATE_DOWN, WONDERTAP_STATE_UP };
enum { WONDERTAP_CACHE_FREQ_SET=1, WONDERTAP_CACHE_TX_RATE_SET=2,
       WONDERTAP_CACHE_BSSID_SET=4, WONDERTAP_CACHE_COUNTRY_CODE_SET=8 };
struct wondertap_data {
 struct mutex lock; int state; unsigned int cache_flags;
 struct wondertap_set_freq_params cached_freq;
 struct wondertap_fixed_tx_rate_params cached_tx_rate;
 u8 cached_bssid[6], mac_addr[6]; char cached_country_code[3]; void *vendor_handle;
};
static struct wondertap_init_params observed;
static int calls, fail_code, mask_code;
static int mock_init(void **h, const struct wondertap_init_params *p) {
 observed=*p; calls++; if(!fail_code) *h=(void*)1; return fail_code;
}
static int mock_mask(void *h, const struct wondertap_tx_rate_mask_params *p) {
 (void)h; (void)p; return mask_code;
}
'''
MAIN = r'''
int main(void) {
 struct wondertap_ops ops = {.init=mock_init, .set_tx_rate_mask=mock_mask};
 struct wondertap_init_params in;
 struct wondertap_tx_rate_mask_params mask = {.max_preamble=2,.max_bw=1,.max_nss=1,.max_mcs=2};
 struct wondertap_data w;
 int ret, ra, failure;
 wondertap_register_ops(&ops);
 for (ra=0;ra<2;ra++) {
  memset(&w,0,sizeof(w)); w.cache_flags=15;
  w.cached_freq.freq=5745; w.cached_tx_rate.preamble=2; w.cached_tx_rate.bw=1;
  w.cached_tx_rate.nss=1; w.cached_tx_rate.mcs=2; memcpy(w.cached_country_code,"US",3);
  memset(&in,0xa5,sizeof(in)); /* Caller does NOT initialize the other fields. */
  in.rate_adaptation_enable=ra; in.amsdu_enable=1; in.ampdu_enable=1;
  ret=wondertap_init(&w,&in);
  printf("init %d %d %u %u %u %u %u %d\n",ra,ret,observed.mgmt_retry_limit,
   observed.data_retry_limit,observed.rate_adaptation_enable,observed.amsdu_enable,
   observed.ampdu_enable,w.lock.held);
 }
 for(failure=0;failure<2;failure++) {
  memset(&w,0,sizeof(w)); w.state=WONDERTAP_STATE_UP;
  mask_code=failure ? -EPERM : 0;
  ret=wondertap_set_tx_rate_mask(&w,&mask);
  printf("mask %d %d %d\n",failure,ret,w.lock.held);
 }
 memset(&w,0,sizeof(w)); w.cache_flags=15;
 calls=0; sleeps=0; fail_code=-EIO;
 ret=wondertap_init(&w,&in);
 printf("failed-init %d %d %u %d %d\n",ret,calls,sleeps,w.lock.held,w.state);
 calls=0; w.cache_flags=0; ret=wondertap_init(&w,&in);
 printf("missing-cache %d %d %d\n",ret,calls,w.lock.held);
#if PATCHED
 ret=wondertap_init(&w,NULL); printf("null-init %d %d\n",ret,w.lock.held);
#endif
 return 0;
}
'''
def run(source, patched):
    # Only replace includes; all tested function bodies are from the real source.
    body='\n'.join(x for x in source.splitlines() if not x.startswith('#include'))
    text=PRE.replace('API_HEADER',str(HEADER))+'\n'+body+'\n'+MAIN
    with tempfile.TemporaryDirectory() as td:
        p=Path(td); (p/'test.c').write_text(text)
        r=subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror',
            '-Wno-unused-parameter','-ftrivial-auto-var-init=pattern','-O0',
            '-DPATCHED='+str(int(patched)),str(p/'test.c'),'-o',str(p/'test')],capture_output=True,text=True)
        if r.returncode: raise RuntimeError(r.stderr)
        return subprocess.check_output([str(p/'test')],text=True,timeout=5)
class GenericTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before=run((ROOT/'upstream/op13t-excerpts'/REL).read_text(),False)
        cls.after=run((ROOT/'module/staged-source'/REL).read_text(),True)
        (ROOT/'evidence/generic-c-regression.json').write_text(json.dumps({
           'scope':'Host C with real API header; patterned auto-initialization for deterministic defect reproduction',
           'pristine':cls.before,'patched':cls.after},indent=2)+'\n')
    def test_original_lock_leak_reproduced(self):
        self.assertIn('mask 0 0 1',self.before)
        self.assertIn('mask 1 -1 1',self.before)
    def test_lock_released_success_and_error(self):
        self.assertIn('mask 0 0 0',self.after)
        self.assertIn('mask 1 -1 0',self.after)
    def test_initialized_params_and_capability_flags(self):
        self.assertIn('init 0 0 0 0 0 1 1 0',self.after)
        self.assertIn('init 1 0 0 0 1 1 1 0',self.after)
        self.assertNotIn('init 0 0 0 0 0 1 1 0',self.before)
    def test_retry_bound_and_cleanup(self):
        self.assertIn('failed-init -5 4 3 0 0',self.after)
        self.assertIn('failed-init -5 4 4 0 0',self.before)
    def test_invalid_input_never_calls_provider(self):
        self.assertIn('missing-cache -22 0 0',self.after)
        self.assertIn('null-init -22 0',self.after)
if __name__=='__main__': unittest.main()
