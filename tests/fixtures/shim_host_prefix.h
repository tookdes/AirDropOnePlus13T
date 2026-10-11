/* Host-only sequential lifecycle mock. Never a kernel build or load test. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <arpa/inet.h>
#define OP13T_SYNTAX_SMOKE_ONLY 1
#define __init
#define __exit
#define GFP_KERNEL 0
#define PLATFORM_DEVID_NONE (-1)
#define THIS_MODULE ((void *)1)
#define DEFINE_MUTEX(name) int name
#define module_param(...)
#define MODULE_PARM_DESC(...)
#define MODULE_LICENSE(...)
#define MODULE_DESCRIPTION(...)
#define EXPORT_SYMBOL(...)
#define module_init(...)
#define module_exit(...)
typedef uint32_t u32;
typedef uint32_t __be32;
struct property { char *name; void *value; int length; };
struct device_node { int refs; unsigned int phandle; struct property *prop, *dead; };
struct device { struct device_node *of_node; void *driver_data; const char *name; };
struct platform_device { struct device dev; };
struct module { int not_a_real_layout; };
struct component_ops {
    int (*bind)(struct device *,struct device *,void *);
    void (*unbind)(struct device *,struct device *,void *);
};
static struct device_node nodes[2]={{.refs=1,.phandle=0x123},{.refs=1,.phandle=0x456}};
static struct platform_device existing;
static int missing_node=-1,occupied_node=-1,alloc_calls,fail_alloc,live_allocs;
static int add_calls,fail_add,fail_property,fail_component,fail_pin;
static int property_adds,property_removes,devices,components,pins;
static int component_add_calls,component_del_calls,existing_puts;
static struct device mock_master={.name="mock-wonder"};
static void mock_log(const char *format,...) { (void)format; }
#define pr_info(...) mock_log(__VA_ARGS__)
#define pr_err(...) mock_log(__VA_ARGS__)
#define dev_info(dev,...) mock_log(__VA_ARGS__)
static const char *dev_name(struct device *dev) { return dev->name; }
static void mutex_lock(int *m) { assert(*m==0); *m=1; }
static void mutex_unlock(int *m) { assert(*m==1); *m=0; }
static bool try_module_get(void *mod) { (void)mod; if(fail_pin)return false; pins++; return true; }
static void module_put(void *mod) { (void)mod; assert(pins>0); pins--; }
static void *mock_alloc(size_t n) {
    alloc_calls++;
    if(fail_alloc==alloc_calls)return NULL;
    void *p=calloc(1,n); assert(p); live_allocs++; return p;
}
static void *kzalloc(size_t n,int flags) { (void)flags; return mock_alloc(n); }
static void *kmalloc(size_t n,int flags) { (void)flags; return mock_alloc(n); }
static char *kstrdup(const char *s,int flags) {
    (void)flags; char *p=mock_alloc(strlen(s)+1); if(p)strcpy(p,s); return p;
}
static void kfree(void *p) { if(p){ assert(live_allocs>0); live_allocs--; free(p); } }
static __be32 cpu_to_be32(u32 v) { return htonl(v); }
static void *ERR_PTR(int e) { return (void *)(intptr_t)e; }
static bool IS_ERR(const void *p) { return (uintptr_t)p>=(uintptr_t)-4095; }
static int PTR_ERR(const void *p) { return (int)(intptr_t)p; }
static struct device_node *of_node_get(struct device_node *np) { if(np)np->refs++; return np; }
static void of_node_put(struct device_node *np) { if(np){assert(np->refs>1); np->refs--;} }
static struct device_node *of_find_node_by_path(const char *path) {
    int i=strstr(path,"cnss_host_sol_default")?0:1;
    if(i==missing_node)return NULL;
    return of_node_get(&nodes[i]);
}
static int of_property_read_u32(struct device_node *np,const char *key,u32 *out) {
    (void)key; *out=np->phandle; return 0;
}
static struct platform_device *of_find_device_by_node(struct device_node *np) {
    if(occupied_node>=0 && np==&nodes[occupied_node])return &existing;
    return NULL;
}
static void put_device(struct device *dev) { assert(dev==&existing.dev); existing_puts++; }
static struct property *of_find_property(struct device_node *np,const char *name,int *len) {
    (void)name; (void)len; return np->prop;
}
static int of_add_property(struct device_node *np,struct property *p) {
    if(fail_property || np->prop)return -EEXIST;
    np->prop=p; property_adds++; return 0;
}
static int of_remove_property(struct device_node *np,struct property *p) {
    assert(np->prop==p); assert(!np->dead);
    np->prop=NULL; np->dead=p; property_removes++; return 0;
}
static struct platform_device *platform_device_alloc(const char *name,int id) {
    (void)id; struct platform_device *p=mock_alloc(sizeof(*p));
    if(p)p->dev.name=name;
    return p;
}
static int platform_device_add(struct platform_device *p) {
    assert(p); add_calls++; if(add_calls==fail_add)return -EIO; devices++; return 0;
}
static void platform_device_put(struct platform_device *p) { of_node_put(p->dev.of_node); kfree(p); }
static void platform_device_unregister(struct platform_device *p) {
    assert(devices>0); devices--; platform_device_put(p);
}
static void *platform_get_drvdata(struct platform_device *p) { return p->dev.driver_data; }
static void platform_set_drvdata(struct platform_device *p,void *data) { p->dev.driver_data=data; }
static int component_add(struct device *dev,const struct component_ops *ops) {
    component_add_calls++;
    if(fail_component)return -EIO;
    int ret=ops->bind(dev,&mock_master,NULL);
    if(ret)return ret;
    components++; return 0;
}
static void component_del(struct device *dev,const struct component_ops *ops) {
    assert(components>0); components--; component_del_calls++;
    ops->unbind(dev,&mock_master,NULL);
}
