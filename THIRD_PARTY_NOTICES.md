# Third-party source notices

The five donor source snapshots are copied from the pinned OnePlusOSS SM8850 public source tree. Their copyright and license notices are preserved byte-for-byte. The WonderTap contract header declares GPL-2.0-only; QDF/HDD files carry their original ISC-style notices. The target generic contract is the identical GPL-2.0-only source blob.

The patch files include this source under those existing terms; no relicensing of upstream material is intended. Consult each file header and the linked upstream tree before redistribution. No Qualcomm firmware binaries or Mosey proprietary binaries are included.

The locally written Python tooling, test mocks, reports and fixture-generated metadata are separate from the upstream driver implementation.

The additional target `wondertap.c` snapshot is byte-exact from the pinned OnePlusOSS SM8750 generic Wonder tree. Its existing file contents are preserved; consult that upstream tree's licensing for the original implementation. The new 13T helper sources are marked GPL-2.0-only. Their architectural reference is 34306/AirDropVivoCN's GPL shim, but they deliberately do not copy its vivo-specific stubs or hard-coded structure offsets.
