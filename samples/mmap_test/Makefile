include ../../Defines.mk

current_dir = $(shell pwd)

all : test

cosmix:
	make -C ../../pass -f Makefile SDK_BUILD="-DSCONE_BUILD" NO_COUNTERS="-DNO_COUNTERS" STORAGE_MMAP_FILE_PATH="-DSTORAGE_MMAP_FILE_PATH=\\\"test.dat\\\"";
	make -C ../../runtime -f Makefile SDK_BUILD="-DSCONE_BUILD" NO_COUNTERS="-DNO_COUNTERS" STORAGE_MMAP_FILE_PATH="-DSTORAGE_MMAP_FILE_PATH=\\\"test.dat\\\"";
	make -C ../../mstores -f Makefile SDK_BUILD="-DSCONE_BUILD" NO_COUNTERS="-DNO_COUNTERS" STORAGE_MMAP_FILE_PATH="-DSTORAGE_MMAP_FILE_PATH=\\\"test.dat\\\"";

test: test.c cosmix
	$(LLVM_BIN)/clang -O3 -emit-llvm -c test.c -o test.bc
	$(LLVM_BIN)/llvm-link test.bc ../../runtime/cosmix_runtime.bc ../../mstores/common/common.bc ../../mstores/storage/storage_runtime.bc -o test_wrappers.bc
	$(LLVM_BIN)/opt < test_wrappers.bc -gvn -gvn-hoist -gvn-sink -loop-simplify -licm > test_loop_simplify.bc
	$(LLVM_BIN)/opt -load ../../pass/cosmix.so < test_loop_simplify.bc -cosmix -replace_all_allocators=false -code_analysis_integers=false -config_file=$(current_dir)/mmap.json > test_inst.bc
	$(LLVM_BIN)/llc -relocation-model=pic -filetype=obj test_inst.bc -o test.o
	g++ test.o -o test -L../../libs -lcrypto

clean:
	make -C ../../pass -f Makefile clean
	make -C ../../runtime -f Makefile clean
	rm -rf *.bc *.o *.log *.bin test
