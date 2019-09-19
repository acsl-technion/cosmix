include ../Defines.mk 
	  
.PHONY: clean all
		 
ifneq ($(SDK_BUILD), -DSDK_BUILD)
all:
	$(MAKE) -C common $@;
	$(MAKE) -C suvm $@;
	$(MAKE) -C storage $@;
	$(MAKE) -C oram $@;
	$(CLANG_PATH)/llvm-link common/common.bc suvm/suvm_runtime.bc storage/storage_runtime.bc oram/oram.bc -o mstores.bc 
	
else
all:
	$(MAKE) -C common $@;
	$(MAKE) -C suvm $@;
endif
					  
clean:
	$(MAKE) -C common clean;
	$(MAKE) -C suvm clean;
	$(MAKE) -C storage clean;
	$(MAKE) -C oram clean;
	rm -rf *.bc
