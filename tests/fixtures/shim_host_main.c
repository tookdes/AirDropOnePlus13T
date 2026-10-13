/* Runs the actual shim source above against the host mocks in this process. */
static void release_mock_deadprops(void) {
    for(int i=0;i<2;i++)if(nodes[i].dead){
        struct property *p=nodes[i].dead;
        kfree(p->name); kfree(p->value); kfree(p); nodes[i].dead=NULL;
    }
}
static void clean(void) {
    assert(!devices && !components && !pins && !provider_lock);
    assert(nodes[0].refs==1 && nodes[1].refs==1);
    release_mock_deadprops(); assert(!live_allocs);
}
int main(int argc,char **argv) {
    assert(argc>=2); const char *test=argv[1]; int ret;
    if(!strcmp(test,"readonly")){
        assert(diagnostics_only); assert(wonder_shim_13t_init()==0);
        assert(!alloc_calls && !property_adds && !add_calls);
        assert(cnss_set_vendor_wonder_priv_data((void *)1)==-ENODEV);
        wonder_shim_13t_exit(); clean();
    }else if(!strcmp(test,"missing")){
        missing_node=atoi(argv[2]); assert(wonder_shim_13t_init()==-ENODEV); clean();
    }else if(!strcmp(test,"occupied")){
        occupied_node=atoi(argv[2]); assert(wonder_shim_13t_init()==-EBUSY);
        assert(existing_puts==1); clean();
    }else if(!strcmp(test,"zero_phandle")){
        nodes[0].phandle=0; assert(wonder_shim_13t_init()==-EINVAL); clean();
    }else if(!strcmp(test,"existing_property")){
        struct property foreign={0}; nodes[1].prop=&foreign;
        assert(wonder_shim_13t_init()==-EEXIST);
        assert(nodes[1].prop==&foreign && !property_removes); nodes[1].prop=NULL; clean();
    }else if(!strcmp(test,"alloc_fail")){
        diagnostics_only=false; fail_alloc=atoi(argv[2]);
        assert(wonder_shim_13t_init()==-ENOMEM); clean();
    }else if(!strcmp(test,"device_fail")){
        diagnostics_only=false; fail_add=atoi(argv[2]);
        assert(wonder_shim_13t_init()==-EIO);
        assert(property_adds==1 && property_removes==1); clean();
    }else if(!strcmp(test,"property_fail")){
        diagnostics_only=false; fail_property=1;
        assert(wonder_shim_13t_init()==-EEXIST); assert(!add_calls); clean();
    }else if(!strcmp(test,"component_fail")){
        diagnostics_only=false; assert(wonder_shim_13t_init()==0); fail_component=1;
        assert(cnss_set_vendor_wonder_priv_data((void *)1)==-EIO);
        assert(!platform_get_drvdata(provider_pdev) && !component_registered);
        wonder_shim_13t_exit(); clean();
    }else if(!strcmp(test,"pin_fail")){
        diagnostics_only=false; assert(wonder_shim_13t_init()==0); fail_pin=1;
        assert(cnss_set_vendor_wonder_priv_data((void *)1)==-ENODEV);
        assert(!platform_get_drvdata(provider_pdev) && !component_registered);
        wonder_shim_13t_exit(); clean();
    }else if(!strcmp(test,"lifecycle")){
        diagnostics_only=false; assert(wonder_shim_13t_init()==0);
        assert(devices==2 && nodes[0].refs==3 && nodes[1].refs==3);
        assert(cnss_set_vendor_wonder_priv_data((void *)1)==0);
        assert(components==1 && pins==1 && component_add_calls==1);
        assert(cnss_set_vendor_wonder_priv_data((void *)1)==0);
        assert(component_add_calls==1);
        assert(cnss_set_vendor_wonder_priv_data((void *)2)==-EBUSY);
        assert(platform_get_drvdata(provider_pdev)==(void *)1);
        assert(cnss_set_vendor_wonder_priv_data(NULL)==0);
        assert(!components && !pins && component_del_calls==1);
        assert(cnss_set_vendor_wonder_priv_data(NULL)==0);
        assert(component_del_calls==1);
        assert(cnss_set_vendor_wonder_priv_data((void *)2)==0);
        wonder_shim_13t_exit(); clean();
        assert(property_adds==1 && property_removes==1);
    }else if(!strcmp(test,"software_ops")){
        diagnostics_only=false; software_ops=true;
        assert(wonder_shim_13t_init()==0);
        assert(components==1 && component_add_calls==1);
        assert(platform_get_drvdata(provider_pdev)==&software_priv);
        /* Replacing the software stub requires an explicit unregister. */
        assert(cnss_set_vendor_wonder_priv_data((void *)1)==-EBUSY);
        wonder_shim_13t_exit(); software_ops=false; clean();
    }else { ret=1; return ret; }
    printf("PASS %s: sequential host mock, not kernel loadability\n",test);
    return 0;
}
