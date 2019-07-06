include ../Defines.mk 
	  
.PHONY: clean all
		 
all:
	$(MAKE) -C common $@;
	$(MAKE) -C suvm $@;
	$(MAKE) -C storage $@;
	$(MAKE) -C oram $@;
	$(CLANG_PATH)/llvm-link common/common.bc suvm/suvm_runtime.bc storage/storage_runtime.bc oram/oram.bc -o mstores.bc 
					  
clean:
	$(MAKE) -C common clean;
	$(MAKE) -C suvm clean;
	$(MAKE) -C storage clean;
	$(MAKE) -C oram clean;
	rm -rf *.bc
