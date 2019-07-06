include ../../Defines.mk

current_dir = $(shell pwd)

.PHONY: clean all

# Note, this sample was precompiled into a combined LLVM IR file named: memcached_combined_ir.bc using LLVM Gold plugin

all: memcached_native memcached_suvm

cosmix:
	make -C ../../pass -f Makefile SDK_BUILD="-DSCONE_BUILD" NO_COUNTERS="-DNO_COUNTERS" RELEASE_BUILD="-DRELEASE_BUILD" ASYNC_EVICTS="-DASYNC_EVICTS" SUVM_PAGE_CACHE_BITS="-DSUVM_PAGE_CACHE_BITS=25";
	make -C ../../runtime -f Makefile SDK_BUILD="-DSCONE_BUILD" NO_COUNTERS="-DNO_COUNTERS" RELEASE_BUILD="-DRELEASE_BUILD" ASYNC_EVICTS="-DASYNC_EVICTS" SUVM_PAGE_CACHE_BITS="-DSUVM_PAGE_CACHE_BITS=25";
	make -C ../../mstores -f Makefile SDK_BUILD="-DSCONE_BUILD" NO_COUNTERS="-DNO_COUNTERS" RELEASE_BUILD="-DRELEASE_BUILD" ASYNC_EVICTS="-DASYNC_EVICTS" SUVM_PAGE_CACHE_BITS="-DSUVM_PAGE_CACHE_BITS=25";

memcached_suvm: memcached_combined_ir.bc cosmix
	$(LLVM_BIN)/llvm-link memcached_combined_ir.bc ../../runtime/cosmix_runtime.bc -o test_wrappers.bc
	$(LLVM_BIN)/opt < test_wrappers.bc -gvn -gvn-hoist -gvn-sink -loop-simplify -licm > test_loop_simplify.bc
	$(LLVM_BIN)/opt -load ../../pass/cosmix.so < test_loop_simplify.bc -cosmix -replace_all_allocators=false -code_analysis_integers=false -config_file=$(current_dir)/suvm.json > test_inst.bc
	$(LLVM_BIN)/llvm-link test_inst.bc ../../mstores/common/common.bc ../../mstores/suvm/suvm_runtime.bc -o test_wrappers.bc
	$(LLVM_BIN)/opt -load ../../pass/cosmix.so < test_wrappers.bc -cosmix -fix_real_functions=true > test_inst.bc
	$(LLVM_BIN)/opt -O3 < test_inst.bc > test_opt.bc
	$(LLVM_BIN)/llc -relocation-model=pic -filetype=obj test_opt.bc -o test.o
	echo "g++ COSMIX => memcached_suvm"
	g++ test.o -o memcached_suvm -L/usr/src/myapp -L../../libs -L../../../event/lib -lpthread -levent -lsgx_tcrypto

memcached_native : memcached_combined_ir.bc temp.c
	$(LLVM_BIN)/clang -emit-llvm -c temp.c -o temp.bc
	$(LLVM_BIN)/llvm-link memcached_combined_ir.bc temp.bc -o memcached_wrappers.bc
	$(LLVM_BIN)/llc -relocation-model=pic -filetype=obj memcached_wrappers.bc -o memcached.o
	echo "g++ => memcached_native"
	g++ memcached.o -o memcached_native -L../../../event/lib -lpthread -levent

clean:
	make -C ../../pass -f Makefile clean &> /dev/null;
	make -C ../../runtime -f Makefile clean &> /dev/null;
	make -C ../../mstores -f Makefile clean &> /dev/null;
	rm -rf memcached_simplify.bc memcached_wrappers.bc memcached_inst.bc memcached.o memcached_opt.bc memcached_native memcached_suvm
