include ../../Defines.mk

UnitTest_File := single_source_tests/sumarray.c

.PHONY: all run
all: test
run: all

current_dir = $(shell pwd)

test : $(UnitTest_File)
	$(LLVM_BIN)/clang -O3 -emit-llvm -c $(UnitTest_File) -o test.bc
	$(LLVM_BIN)/llvm-link test.bc ../../runtime/cosmix_runtime.bc ../../mstores/suvm/suvm_runtime.bc ../../mstores/common/common.bc -o test_wrappers.bc
	$(LLVM_BIN)/opt < test_wrappers.bc -gvn -gvn-hoist -gvn-sink -loop-simplify -licm > test_loop_simplify.bc
	$(LLVM_BIN)/opt -load ../../pass/cosmix.so < test_loop_simplify.bc -cosmix -replace_all_allocators=true -code_analysis_integers=true -cross_page_cached_mstores_enabled=true -config_file=$(current_dir)/suvm.json > test_inst.bc
	$(LLVM_BIN)/llc -relocation-model=pic -filetype=obj test_inst.bc -o test.o
	g++ test.o -o test -L../../libs -lsgx_tcrypto -lpthread

clean:
	rm -f *.bc test.o test
