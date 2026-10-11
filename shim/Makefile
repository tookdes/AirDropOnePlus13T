# Invoke through tools/build_stage_a.py with a prepared target output tree.
obj-m += hello_13t.o
ifeq ($(BUILD_WONDER_SHIM),1)
obj-m += wonder_shim_13t.o
endif
ccflags-y += -Werror=incompatible-pointer-types
