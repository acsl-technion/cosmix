include ../../Defines.mk

current_dir = $(shell pwd)

all : oram oram_suvm suvm native storage

cosmix:
	make -C ../../pass -f Makefile SDK_BUILD="-DSCONE_BUILD" NO_COUNTERS="-DNO_COUNTERS" RELEASE_BUILD="-DRELEASE_BUILD" SUVM_MIN_PTR_SIZE="-DSUVM_MIN_PTR_SIZE=1" SUVM_MAX_PTR_SIZE="-DSUVM_MAX_PTR_SIZE=1073741824" ORAM_BITS="-DORAM_BITS=28";
	make -C ../../runtime -f Makefile SDK_BUILD="-DSCONE_BUILD" NO_COUNTERS="-DNO_COUNTERS" RELEASE_BUILD="-DRELEASE_BUILD" SUVM_MIN_PTR_SIZE="-DSUVM_MIN_PTR_SIZE=1" SUVM_MAX_PTR_SIZE="-DSUVM_MAX_PTR_SIZE=1073741824" ORAM_BITS="-DORAM_BITS=28";
	make -C ../../mstores -f Makefile SDK_BUILD="-DSCONE_BUILD" NO_COUNTERS="-DNO_COUNTERS" RELEASE_BUILD="-DRELEASE_BUILD" SUVM_MIN_PTR_SIZE="-DSUVM_MIN_PTR_SIZE=1" SUVM_MAX_PTR_SIZE="-DSUVM_MAX_PTR_SIZE=1073741824" ORAM_BITS="-DORAM_BITS=28";

native: test.c
	$(LLVM_BIN)/clang -O3 -emit-llvm -c test.c -o test.bc
	$(LLVM_BIN)/llc -relocation-model=pic -filetype=obj test.bc -o test.o
	gcc test.o -o native

suvm: test.c cosmix
	$(LLVM_BIN)/clang -O3 -emit-llvm -c test.c "-DSUVM_TEST" -o test.bc
	$(LLVM_BIN)/llvm-link test.bc ../../runtime/cosmix_runtime.bc ../../mstores/common/common.bc ../../mstores/suvm/suvm_runtime.bc -o test_wrappers.bc
	$(LLVM_BIN)/opt < test_wrappers.bc -gvn -gvn-hoist -gvn-sink -loop-simplify -licm > test_loop_simplify.bc
	$(LLVM_BIN)/opt -load ../../pass/cosmix.so < test_loop_simplify.bc -cosmix -replace_all_allocators=false -code_analysis_integers=false -config_file=$(current_dir)/suvm.json > test_inst.bc
	$(LLVM_BIN)/opt -O3 < test_inst.bc > test_opt.bc
	$(LLVM_BIN)/llc -relocation-model=pic -filetype=obj test_opt.bc -o test.o
	g++ test.o -o suvm -L../../libs -lsgx_tcrypto	

storage: test.c cosmix
	$(LLVM_BIN)/clang -O3 -emit-llvm -c test.c "-DSTORAGE_TEST" -o test.bc
	$(LLVM_BIN)/llvm-link test.bc ../../runtime/cosmix_runtime.bc ../../mstores/common/common.bc ../../mstores/storage/storage_runtime.bc -o test_wrappers.bc
	$(LLVM_BIN)/opt < test_wrappers.bc -gvn -gvn-hoist -gvn-sink -loop-simplify -licm > test_loop_simplify.bc
	$(LLVM_BIN)/opt -load ../../pass/cosmix.so < test_loop_simplify.bc -cosmix -replace_all_allocators=false -code_analysis_integers=false -config_file=$(current_dir)/mmap.json > test_inst.bc
	$(LLVM_BIN)/opt -O3 < test_inst.bc > test_opt.bc
	$(LLVM_BIN)/llc -relocation-model=pic -filetype=obj test_opt.bc -o test.o
	g++ test.o -o storage -L../../runtime 

oram: test.c cosmix
	$(LLVM_BIN)/clang -O3 -emit-llvm -c test.c "-DORAM_TEST" -o test.bc
	$(LLVM_BIN)/llvm-link test.bc ../../runtime/cosmix_runtime.bc ../../mstores/oram/oram.bc ../../mstores/common/common.bc -o test_wrappers.bc
	$(LLVM_BIN)/opt < test_wrappers.bc -gvn -gvn-hoist -gvn-sink -loop-simplify -licm > test_loop_simplify.bc
	$(LLVM_BIN)/opt -load ../../pass/cosmix.so < test_loop_simplify.bc -cosmix -replace_all_allocators=false -code_analysis_integers=false -config_file=$(current_dir)/oram.json > test_inst.bc
	$(LLVM_BIN)/opt -O3 < test_inst.bc > test_opt.bc
	$(LLVM_BIN)/llc -relocation-model=pic -filetype=obj test_opt.bc -o test.o
	g++ test.o -o oram

oram_suvm: test.c cosmix
	rm -rf ../../mstores/oram/oram.bc
	make -C ../../mstores -f Makefile NO_COUNTERS="-DNO_COUNTERS" RELEASE_BUILD="-DRELEASE_BUILD" ORAM_UNTRUSTED="-DORAM_UNTRUSTED" ORAM_BITS="-DORAM_BITS=28";
	$(LLVM_BIN)/clang -O3 -emit-llvm -c test.c "-DORAM_TEST" -o test.bc
	$(LLVM_BIN)/llvm-link test.bc ../../runtime/cosmix_runtime.bc ../../mstores/oram/oram.bc ../../mstores/common/common.bc -o test_wrappers.bc
	#$(LLVM_BIN)/opt < test_wrappers.bc -gvn -gvn-hoist -gvn-sink -loop-simplify -licm > test_loop_simplify.bc
	$(LLVM_BIN)/opt -load ../../pass/cosmix.so < test_wrappers.bc -cosmix -replace_all_allocators=false -code_analysis_integers=false -config_file=$(current_dir)/oram_suvm.json > test_inst.bc
	$(LLVM_BIN)/llvm-link test_inst.bc ../../mstores/suvm/suvm_runtime.bc -o test_wrappers.bc
	$(LLVM_BIN)/opt -load ../../pass/cosmix.so < test_wrappers.bc -cosmix -fix_real_functions=true > test_inst.bc
	$(LLVM_BIN)/opt -O3 < test_inst.bc > test_opt.bc
	$(LLVM_BIN)/llc -relocation-model=pic -filetype=obj test_opt.bc -o test.o
	g++ test.o -o oram_suvm -L../../libs -lsgx_tcrypto

clean:
	make -C ../../pass -f Makefile clean &> /dev/null;
	make -C ../../runtime -f Makefile clean &> /dev/null;
	rm -rf *.bc *.o *.log *.bin oram oram_suvm suvm storage native
