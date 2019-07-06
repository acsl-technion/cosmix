HOME=/home/user
LLVM_PATH=$(HOME)/llvm/bin
export LLVM_PATH
CLANG_PATH=$(HOME)/llvm/bin
export CLANG_PATH
LLVM_INC=$(HOME)/llvm/include
export LLVM_INC
LLVM_BIN=$(HOME)/llvm/bin
export LLVM_BIN

SVF_DIR=../SVF
export SVF_DIR

SGX_SDK ?= /opt/intel/sgxsdk
export SGX_SDK
SGX_MODE ?= HW
export SGX_MODE
SGX_PRERELEASE=1
export SGX_PRERELEASE
SGX_ARCH ?= x64
export SGX_ARCH
 
# to disable asserts,etc uncomment
#RELEASE_BUILD ?= "-DRELEASE_BUILD"
#export RELEASE_BUILD

# to disable counter printing uncomment
NO_COUNTERS ?= "-DNO_COUNTERS"
export PRINT_COUNTERS
