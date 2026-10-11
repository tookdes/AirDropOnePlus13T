// SPDX-License-Identifier: GPL-2.0-only
/*
 * Runtime provider glue for the target's existing DT nodes.
 * Architecture reference: 34306/AirDropVivoCN/on-device/src/wonder_shim.c.
 * Reimplemented with typed kernel APIs, explicit OF reference ownership,
 * propagated component errors, and a read-only default.
 *
 * This source is NOT proof of stock-kernel ABI or radio compatibility.
 * Full mode must not run before the firmware/driver/ABI validation gates.
 */
#include <linux/component.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include "include/target_guard.h"

/* Generated only from reviewed, captured target layout evidence. */
#ifndef OP13T_SYNTAX_SMOKE_ONLY
#include "include/target_layout.generated.h"
static_assert(offsetof(struct platform_device, dev) == OP13T_PLATFORM_DEV_OFFSET);
static_assert(offsetof(struct device, driver_data) == OP13T_DEVICE_DRIVER_DATA_OFFSET);
static_assert(offsetof(struct device, of_node) == OP13T_DEVICE_OF_NODE_OFFSET);
static_assert(sizeof(struct module) == OP13T_MODULE_SIZE);
#endif

#define PROVIDER_PROP "wondertap-provider"
static bool diagnostics_only = true;
module_param(diagnostics_only, bool, 0444);
MODULE_PARM_DESC(diagnostics_only, "Read-only DT diagnostics; default true, no devices/properties created");
static char *provider_node = "/soc/pinctrl@f000000/cnss_pins/cnss_host_sol_default";
module_param(provider_node, charp, 0444);
static char *wonder_node = "/soc/pinctrl@f000000/cnss_pins";
module_param(wonder_node, charp, 0444);

static DEFINE_MUTEX(provider_lock);
static struct device_node *provider_np, *wonder_np;
static struct platform_device *provider_pdev, *wonder_pdev;
static struct property *provider_prop;
static bool component_registered;

static int shim_bind(struct device *dev, struct device *master, void *data)
{
	/* Prevent this provider from disappearing while the master is bound. */
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;
	dev_info(dev, "bound to %s\n", dev_name(master));
	return 0;
}

static void shim_unbind(struct device *dev, struct device *master, void *data)
{
	dev_info(dev, "unbound from %s\n", dev_name(master));
	module_put(THIS_MODULE);
}

static const struct component_ops provider_ops = {
	.bind = shim_bind,
	.unbind = shim_unbind,
};

/* Same prototype as the donor cnss2.h, including const. No KCFI casts. */
int cnss_set_vendor_wonder_priv_data(const void *data);
int cnss_set_vendor_wonder_priv_data(const void *data)
{
	int ret = 0;

	mutex_lock(&provider_lock);
	if (diagnostics_only || !provider_pdev) {
		ret = -ENODEV;
		goto out;
	}
	if (data && component_registered) {
		/* Replacing live vendor callbacks requires an explicit unregister. */
		ret = platform_get_drvdata(provider_pdev) == data ? 0 : -EBUSY;
		goto out;
	}
	if (component_registered) {
		component_del(&provider_pdev->dev, &provider_ops);
		component_registered = false;
	}
	/* The callback contract is const; the device API stores an opaque pointer. */
	platform_set_drvdata(provider_pdev, (void *)data);
	if (data) {
		ret = component_add(&provider_pdev->dev, &provider_ops);
		if (ret)
			platform_set_drvdata(provider_pdev, NULL);
		else
			component_registered = true;
	}
out:
	mutex_unlock(&provider_lock);
	return ret;
}
EXPORT_SYMBOL(cnss_set_vendor_wonder_priv_data);

static struct property *alloc_provider_property(u32 phandle)
{
	struct property *prop = kzalloc(sizeof(*prop), GFP_KERNEL);
	__be32 *value;

	if (!prop)
		return NULL;
	prop->name = kstrdup(PROVIDER_PROP, GFP_KERNEL);
	value = kmalloc(sizeof(*value), GFP_KERNEL);
	if (!prop->name || !value) {
		kfree(prop->name);
		kfree(value);
		kfree(prop);
		return NULL;
	}
	*value = cpu_to_be32(phandle);
	prop->value = value;
	prop->length = sizeof(*value);
	return prop;
}

static struct platform_device *add_shim_device(const char *name,
					      struct device_node *np)
{
	struct platform_device *pdev;
	int ret;

	pdev = platform_device_alloc(name, PLATFORM_DEVID_NONE);
	if (!pdev)
		return ERR_PTR(-ENOMEM);
	/* platform_device_release() puts this separate node reference. */
	pdev->dev.of_node = of_node_get(np);
	ret = platform_device_add(pdev);
	if (ret) {
		platform_device_put(pdev);
		return ERR_PTR(ret);
	}
	return pdev;
}

static void release_nodes(void)
{
	of_node_put(wonder_np);
	of_node_put(provider_np);
	wonder_np = NULL;
	provider_np = NULL;
}

static void remove_shim_devices(void)
{
	if (wonder_pdev) {
		platform_device_unregister(wonder_pdev);
		wonder_pdev = NULL;
	}
	mutex_lock(&provider_lock);
	if (component_registered) {
		component_del(&provider_pdev->dev, &provider_ops);
		component_registered = false;
	}
	if (provider_pdev) {
		platform_set_drvdata(provider_pdev, NULL);
		platform_device_unregister(provider_pdev);
		provider_pdev = NULL;
	}
	mutex_unlock(&provider_lock);
	if (provider_prop) {
		/* OF retains removed properties on deadprops. Never kfree these. */
		if (of_remove_property(wonder_np, provider_prop))
			pr_err("op13t-wonder: failed to remove owned DT property; reboot required\n");
		provider_prop = NULL;
	}
	release_nodes();
}

static int ensure_unbound(struct device_node *np)
{
	struct platform_device *existing = of_find_device_by_node(np);

	if (!existing)
		return 0;
	put_device(&existing->dev);
	return -EBUSY;
}

static int __init wonder_shim_13t_init(void)
{
	struct platform_device *pdev;
	struct property *prop;
	u32 phandle;
	int ret;

	/* On 6.6 this inline calls of_find_node_opts_by_path(). */
	provider_np = of_find_node_by_path(provider_node);
	wonder_np = of_find_node_by_path(wonder_node);
	ret = -ENODEV;
	if (!provider_np || !wonder_np)
		goto fail_nodes;
	ret = -EINVAL;
	if (provider_np == wonder_np)
		goto fail_nodes;
	ret = of_property_read_u32(provider_np, "phandle", &phandle);
	if (ret)
		goto fail_nodes;
	if (!phandle) {
		ret = -EINVAL;
		goto fail_nodes;
	}
	ret = ensure_unbound(provider_np);
	if (ret)
		goto fail_nodes;
	ret = ensure_unbound(wonder_np);
	if (ret)
		goto fail_nodes;
	if (of_find_property(wonder_np, PROVIDER_PROP, NULL)) {
		ret = -EEXIST;
		goto fail_nodes;
	}
	pr_info("op13t-wonder: DT prerequisites present, phandle=0x%x diagnostics=%d\n",
		phandle, diagnostics_only);
	pr_info("op13t-wonder: compiled layouts: platform.dev=%zu device.driver_data=%zu device.of_node=%zu module=%zu\n",
		offsetof(struct platform_device, dev), offsetof(struct device, driver_data),
		offsetof(struct device, of_node), sizeof(struct module));
	if (diagnostics_only) {
		release_nodes();
		return 0;
	}

	prop = alloc_provider_property(phandle);
	if (!prop) {
		ret = -ENOMEM;
		goto fail_nodes;
	}
	ret = of_add_property(wonder_np, prop);
	if (ret) {
		/* A failed add never links the property (6.6 OF implementation). */
		kfree(prop->name);
		kfree(prop->value);
		kfree(prop);
		goto fail_nodes;
	}
	provider_prop = prop;
	pdev = add_shim_device("wonder-provider-shim13t", provider_np);
	if (IS_ERR(pdev)) {
		ret = PTR_ERR(pdev);
		goto fail_devices;
	}
	provider_pdev = pdev;
	pdev = add_shim_device("wonder", wonder_np);
	if (IS_ERR(pdev)) {
		ret = PTR_ERR(pdev);
		goto fail_devices;
	}
	wonder_pdev = pdev;
	return 0;
fail_devices:
	remove_shim_devices();
	return ret;
fail_nodes:
	release_nodes();
	return ret;
}

static void __exit wonder_shim_13t_exit(void)
{
	remove_shim_devices();
}

module_init(wonder_shim_13t_init);
module_exit(wonder_shim_13t_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("OnePlus 13T Wonder provider bridge; read-only diagnostics by default");
