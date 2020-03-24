include ../../../Defines.mk


current_dir = $(shell pwd)

.PHONY: clean all

all: redis-server_native redis-server_scone redis-server_suvm

SCONE_CXX=docker run --rm --device=/dev/isgx -v "$(current_dir)"/../../..:/usr/src/myapp -w /usr/src/myapp/validation/redis/src sconecuratedimages/crosscompilers:alpine scone-g++

cosmix:
	make -C ../../../pass -f Makefile SDK_BUILD="-DGRAPHENE_BUILD" NO_COUNTERS="-DNO_COUNTERS" SUVM_PAGE_CACHE_BITS="-DSUVM_PAGE_CACHE_BITS=20";
	make -C ../../../runtime -f Makefile SDK_BUILD="-DGRAPHENE_BUILD" NO_COUNTERS="-DNO_COUNTERS" SUVM_PAGE_CACHE_BITS="-DSUVM_PAGE_CACHE_BITS=20";
	make -C ../../../mstores -f Makefile SDK_BUILD="-DGRAPHENE_BUILD" NO_COUNTERS="-DNO_COUNTERS" SUVM_PAGE_CACHE_BITS="-DSUVM_PAGE_CACHE_BITS=20";


# Prebuilt for clarity. To reproduce run the following commands:
# Build REDIS regularly to get the dependencies built correctly. Note, we use fPIC due to current requirement posed by COSMIX.
# cd $(REDIS_DIR) && make MALLOC=libc CC="$(LLVM_BIN)/clang -fPIC " -j
# Next we wil just rebuild REDIS code without its dependencies
# cd $(REDIS_DIR)/src && make clean && make MALLOC=libc CC="$(LLVM_BIN)/clang -flto -g -emit-llvm" -j
# Note, the above build should fail when linking since it instructs the makefile to build LLVM IR code files instead of ELF, so the regular old linker doesn't know how to link IR files. No worries, we will link them manually in the next line into the combined IR file that we can use to build with CoSMIX:
redis-server_blob.bc: 
	$(LLVM_BIN)/llvm-link adlist.o quicklist.o ae.o anet.o dict.o server.o sds.o zmalloc.o lzf_c.o lzf_d.o pqsort.o zipmap.o sha1.o ziplist.o release.o networking.o util.o object.o db.o replication.o rdb.o t_string.o t_list.o t_set.o t_zset.o t_hash.o config.o aof.o pubsub.o multi.o debug.o sort.o intset.o syncio.o cluster.o crc16.o endianconv.o slowlog.o scripting.o bio.o rio.o rand.o memtest.o crc64.o bitops.o sentinel.o notify.o setproctitle.o blocked.o hyperloglog.o latency.o sparkline.o redis-check-rdb.o redis-check-aof.o geo.o lazyfree.o module.o evict.o expire.o geohash.o geohash_helper.o childinfo.o defrag.o siphash.o rax.o t_stream.o listpack.o localtime.o lolwut.o lolwut5.o -o redis-server_blob.bc

redis-server_native: redis-server_blob.bc 
	$(LLVM_BIN)/llc -relocation-model=pic -filetype=obj redis-server_blob.bc -o redis.o
	echo "g++ => redis-server_native"
	g++ -g -ggdb -rdynamic redis.o -o redis-server_native ../deps/hiredis/libhiredis.a ../deps/lua/src/liblua.a -lm -ldl -pthread -lrt

redis-server_suvm: cosmix redis-server_blob.bc
	$(LLVM_BIN)/llvm-link redis-server_blob.bc ../../../runtime/cosmix_runtime.bc -o test_wrappers.bc
	$(LLVM_BIN)/opt < test_wrappers.bc -gvn -gvn-hoist -gvn-sink -loop-simplify -licm > test_loop_simplify.bc
	$(LLVM_BIN)/opt -load ../../../pass/cosmix.so < test_loop_simplify.bc -cosmix -replace_all_allocators=true -code_analysis=false -config_file=$(current_dir)/suvm.json > test_inst.bc
	$(LLVM_BIN)/llvm-link test_inst.bc ../../../mstores/common/common.bc ../../../mstores/suvm/suvm_runtime.bc -o test_wrappers.bc
	$(LLVM_BIN)/opt -load ../../../pass/cosmix.so < test_wrappers.bc -cosmix -fix_real_functions=true > test_inst.bc
	$(LLVM_BIN)/opt -O3 < test_inst.bc > test_opt.bc
	$(LLVM_BIN)/llc -relocation-model=pic -filetype=obj test_opt.bc -o test.o
	echo "CoSMIX+SUVM => redis-server_suvm"
	g++ -g -ggdb -rdynamic test.o -o redis-server_suvm -L../../../libs ../deps/hiredis/libhiredis.a ../deps/lua/src/liblua.a -lm -ldl -pthread -lrt -lsgx_tcrypto

clean:
	make -C ../../../pass -f Makefile clean;
	make -C ../../../runtime -f Makefile clean;
	make -C ../../../mstores -f Makefile clean;
	rm -rf test_opt.bc test_inst.bc test_wrappers.bc test_loop_simplify.bc redis.o redis-server_suvm redis-server_native
