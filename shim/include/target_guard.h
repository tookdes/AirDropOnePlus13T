/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OP13T_TARGET_GUARD_H
#define OP13T_TARGET_GUARD_H
#include <linux/version.h>
#ifndef OP13T_SYNTAX_SMOKE_ONLY
#ifndef CONFIG_ARM64
#error "OnePlus 13T modules require ARM64; host objects are not deployable"
#endif
#if LINUX_VERSION_CODE != KERNEL_VERSION(6, 6, 89)
#error "Unreviewed target kernel: expected 6.6.89"
#endif
#ifndef CONFIG_MODVERSIONS
#error "MODVERSIONS must remain enabled"
#endif
#ifndef CONFIG_CFI_CLANG
#error "Clang CFI must remain enabled"
#endif
#endif
#endif
