include ../../Defines.mk

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
else
	SGX_COMMON_CFLAGS := -m64
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g $(SDK_BUILD) $(RELEASE_BUILD) $(NO_COUNTERS) $(MALLOC_TYPE) $(SUVM_MIN_PTR_SIZE) $(SUVM_MAX_PTR_SIZE) $(ORAM_BITS) $(SUVM_PAGE_CACHE_BITS) $(STORAGE_PAGE_CACHE_BITS) $(STORAGE_DECRYPT) $(ASYNC_EVICTS) $(SUVM_PAGE_BITS) $(STORAGE_MMAP_FILE_PATH) $(DISABLE_TLB) $(COSMIX_MMAP_ALL_FILES)
else
        SGX_COMMON_CFLAGS += -O3 -mavx -msse4 -maes $(SDK_BUILD) $(RELEASE_BUILD) $(NO_COUNTERS) $(MALLOC_TYPE) $(SUVM_MIN_PTR_SIZE) $(SUVM_MAX_PTR_SIZE) $(ORAM_BITS) $(SUVM_PAGE_CACHE_BITS) $(STORAGE_PAGE_CACHE_BITS) $(STORAGE_DECRYPT) $(ASYNC_EVICTS) $(SUVM_PAGE_BITS) $(STORAGE_MMAP_FILE_PATH) $(DISABLE_TLB) $(COSMIX_MMAP_ALL_FILES)
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
Samples_Include_Paths := -I. -I../common  -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx 
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Samples_Include_Paths) -fno-builtin-printf -fPIC -I. 
Samples_Cpp_Flags :=  $(Common_C_Cpp_Flags) -nostdinc++ -std=c++11 -fno-builtin-printf -fpermissive -I.
else 
Samples_Include_Paths := -I. -I../common -I$(SGX_SDK)/include
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -fvisibility=hidden -fpie -fstack-protector $(Samples_Include_Paths) -fno-builtin-printf -fPIC -I. 
Samples_Cpp_Flags :=  $(Common_C_Cpp_Flags) -std=c++11 -fno-builtin-printf -fpermissive -I. 
endif

Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11 
Samples_C_Flags := $(Flags_Just_For_C) $(Common_C_Cpp_Flags)
Samples_Cpp_Flags := $(Samples_Cpp_Flags) -fno-builtin-printf -fPIC 

.PHONY: all run

all: suvm_runtime.bc

run: all

######## samples Objects ########

suvm_runtime.bc : suvm_runtime.cpp
	$(CLANG_PATH)/clang++ $(Samples_Cpp_Flags) -fpie -fPIC $(Samples_Include_Paths) -emit-llvm -c $< -o $@
	$(shell ln -s $(SGX_SDK)/lib64/libsgx_tcrypto.a ../../libs/)

clean:
	rm -f *.a *.o *.bc
