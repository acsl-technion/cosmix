include ../../Defines.mk
#LLVM_BIN=/home/meni/llvm/bin

current_dir = $(shell pwd)

all : test

cosmix:
	make -C ../../pass -f Makefile SDK_BUILD="" NO_COUNTERS="-DNO_COUNTERS";
	make -C ../../runtime -f Makefile SDK_BUILD="" NO_COUNTERS="-DNO_COUNTERS";

test: test.c cosmix
	$(LLVM_BIN)/clang -O3 -emit-llvm -c test.c -o test.bc
	$(LLVM_BIN)/llvm-link test.bc ../../runtime/cosmix_runtime.bc ../../mstores/suvm/suvm_runtime.bc ../../mstores/common/common.bc -o test_wrappers.bc
	$(LLVM_BIN)/opt < test_wrappers.bc -gvn -gvn-hoist -gvn-sink -loop-simplify -licm > test_loop_simplify.bc
	$(LLVM_BIN)/opt -load ../../pass/cosmix.so < test_loop_simplify.bc -cosmix -replace_all_allocators=false -code_analysis_integers=false -config_file=$(current_dir)/suvm.json > test_inst.bc
	$(LLVM_BIN)/llc -relocation-model=pic -filetype=obj test_inst.bc -o test.o
	g++ test.o -o test -L../../libs -lsgx_tcrypto

clean:
	make -C ../../pass -f Makefile clean
	make -C ../../runtime -f Makefile clean
	rm -rf *.bc *.o *.log *.bin test
