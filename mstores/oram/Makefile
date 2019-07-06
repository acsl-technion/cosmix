include ../../Defines.mk

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g $(SDK_BUILD) $(RELEASE_BUILD) $(NO_COUNTERS) $(MALLOC_TYPE) $(SUVM_MIN_PTR_SIZE) $(SUVM_MAX_PTR_SIZE) $(ORAM_BITS) $(SUVM_PAGE_CACHE_BITS) $(STORAGE_PAGE_CACHE_BITS) $(STORAGE_DECRYPT) $(ASYNC_EVICTS) $(COSMIX_PAGE_BITS) $(STORAGE_MMAP_FILE_PATH) $(DISABLE_TLB) $(COSMIX_MMAP_ALL_FILES) $(ORAM_UNTRUSTED)
else
        SGX_COMMON_CFLAGS += -O0 -mavx -msse4 -maes $(SDK_BUILD) $(RELEASE_BUILD) $(NO_COUNTERS) $(MALLOC_TYPE) $(SUVM_MIN_PTR_SIZE) $(SUVM_MAX_PTR_SIZE) $(ORAM_BITS) $(SUVM_PAGE_CACHE_BITS) $(STORAGE_PAGE_CACHE_BITS) $(STORAGE_DECRYPT) $(ASYNC_EVICTS) $(COSMIX_PAGE_BITS) $(STORAGE_MMAP_FILE_PATH) $(DISABLE_TLB) $(COSMIX_MMAP_ALL_FILES) $(ORAM_UNTRUSTED)
endif


ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto

current_dir := $(shell pwd)
ifeq ($(SDK_BUILD), -DSCONE_BUILD)
CC= docker run --rm --device=/dev/isgx -v "$(current_dir)"/..:/usr/src/myapp -v "$(SGX_SDK)":/"$(SGX_SDK)" -w /usr/src/myapp/runtime sconecuratedimages/crosscompilers:scone scone-gcc 
CXX=docker run --rm --device=/dev/isgx -v "$(current_dir)"/..:/usr/src/myapp -v "$(SGX_SDK)":/"$(SGX_SDK)" -w /usr/src/myapp/runtime sconecuratedimages/crosscompilers:scone scone-g++
else ifeq ($(SDK_BUILD), -DSCONE_ALPINE_BUILD)
CC= docker run --rm --device=/dev/isgx -v "$(current_dir)"/..:/usr/src/myapp -v "$(SGX_SDK)":/"$(SGX_SDK)" -w /usr/src/myapp/runtime sconecuratedimages/crosscompilers:alpine scone-gcc 
CXX=docker run --rm --device=/dev/isgx -v "$(current_dir)"/..:/usr/src/myapp -v "$(SGX_SDK)":/"$(SGX_SDK)" -w /usr/src/myapp/runtime sconecuratedimages/crosscompilers:alpine scone-g++
else
CC=gcc
CXX=g++
endif

ifeq ($(SDK_BUILD), -DSDK_BUILD)
SGX_COMMON_CFLAGS += -DSGX
Samples_Include_Paths := -I. -I../common
#-IInclude -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Samples_Include_Paths) -fno-builtin-printf -fPIC -I. 
Samples_Cpp_Flags :=  $(Common_C_Cpp_Flags) -nostdinc++ -std=c++11 -fno-builtin-printf -fpermissive -I.
else 
Samples_Include_Paths := -I. -I../common
#-IInclude -I$(SGX_SDK)/include
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -fvisibility=hidden -fpie -fstack-protector $(Samples_Include_Paths) -fno-builtin-printf -fPIC -I. 
Samples_Cpp_Flags :=  $(Common_C_Cpp_Flags) -std=c++11 -fno-builtin-printf -fpermissive -I. 
endif

Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11 
Samples_C_Flags := $(Flags_Just_For_C) $(Common_C_Cpp_Flags)
Samples_Cpp_Flags := $(Samples_Cpp_Flags) -fno-builtin-printf -fPIC 

Samples_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: oram.bc
	@echo "Build enclave samples.so  [$(Build_Mode)|$(SGX_ARCH)] success!"
	@echo
	@echo "*********************************************************************************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the samples.so first using Two Step Sign mechanism before you run the app to launch and access the enclave."
	@echo "*********************************************************************************************************************************************************"
	@echo 


else
all: oram.bc
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/app
	@echo "RUN  =>  app [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## samples Objects ########

oram.bc : oram.cpp
	$(CLANG_PATH)/clang++ $(Samples_Cpp_Flags)  -fpie -fPIC $(Samples_Include_Paths) -emit-llvm -c $< -o temp.bc
	$(CLANG_PATH)/opt -mem2reg temp.bc -o $@

oram_tests: oram_tests.cpp oram.h oram.cpp oram_tests.h 
	$(CXX) -g2 -std=c++11 -fno-exceptions -DORAM_TESTS -o $@ $< oram.cpp ../common/slab_allocator.cpp ../common/SyncUtils.cpp

oram_prof: oram_prof.cpp oram.cpp oram.h oram_tests.h
	$(CXX) -g2 -std=c++11 -fno-exceptions -DORAM_TESTS -o $@ $< oram.cpp

oram_prof.svg: oram_prof gen_flame.sh
	./gen_flame.sh ./$< $@

clean_perf:
	rm -f oram.svg out.perf-folded perf.data perf.data.old
	rm -f oram_tests
	rm -f oram_prof.svg oram_prof
ifeq ($(shell uname), Darwin)
	rm -r oram_tests.dSYM
endif


clean: clean_perf
	rm -f *.a *.o *.bc
