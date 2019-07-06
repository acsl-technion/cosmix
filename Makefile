ALL_PASS_MK=pass/Makefile
ALL_RUNTIME_MK=runtime/Makefile
ALL_MSTORES_MK=mstores/Makefile

include Defines.mk 
	  
.PHONY: clean all SVF
		
all:
	$(MAKE) -C $(shell dirname $(ALL_PASS_MK)) -f $(shell basename $(ALL_PASS_MK)) $@;
	$(MAKE) -C $(shell dirname $(ALL_RUNTIME_MK)) -f $(shell basename $(ALL_RUNTIME_MK)) $@;
	$(MAKE) -C $(shell dirname $(ALL_MSTORES_MK)) -f $(shell basename $(ALL_MSTORES_MK)) $@;
	@echo "CoSMIX Built Succesfully!"					  
clean:
	$(MAKE) -C $(shell dirname $(ALL_PASS_MK)) -f $(shell basename $(ALL_PASS_MK)) clean;
	$(MAKE) -C $(shell dirname $(ALL_RUNTIME_MK)) -f $(shell basename $(ALL_RUNTIME_MK)) clean;
	$(MAKE) -C $(shell dirname $(ALL_MSTORES_MK)) -f $(shell basename $(ALL_MSTORES_MK)) clean;

