// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/module.h>
#include "include/target_guard.h"

static int __init hello_13t_init(void)
{
	pr_info("op13t-wonder: Stage A hello init; no radio operations\n");
	return 0;
}

static void __exit hello_13t_exit(void)
{
	pr_info("op13t-wonder: Stage A hello exit\n");
}

module_init(hello_13t_init);
module_exit(hello_13t_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("OnePlus 13T Stage A ABI probe; does not enable AirDrop");
