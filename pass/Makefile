include ../Defines.mk

SOURCES = cosmix.cpp
LIB_NAME = cosmix.so

LDFLAGS = $(shell $(LLVM_BIN)/llvm-config --ldflags) -L$(SVF_DIR)/Release-build/lib -L$(SVF_DIR)/Release-build/lib/CUDD -Wl,--whole-archive -lLLVMSvf -Wl,--no-whole-archive -Wl,--whole-archive -lLLVMCudd -Wl,--no-whole-archive
CXXFLAGS = -I$(LLVM_INC) -I$(SVF_DIR)/include -Wnon-virtual-dtor -Wunused-variable -Wunused-but-set-variable -Wcomment  -fPIC -fvisibility-inlines-hidden -Werror=date-time -std=c++11 -Wall -W -Wno-unused-parameter -Wwrite-strings -Wcast-qual -Wmissing-field-initializers -pedantic -Wno-long-long  -Wnon-virtual-dtor -Wdelete-non-virtual-dtor -ffunction-sections -fdata-sections -O3 -DNDEBUG  -fno-exceptions -fno-rtti -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS -ggdb3 -Wall -fno-rtti -fPIC -shared -D_GLIBCXX_USE_CXX11_ABI=1

all: $(LIB_NAME) 

jsoncpp.o: jsoncpp.cpp
	g++ -std=c++11 -fexceptions -fPIC -c $^ -o $@

cosmix.o: cosmix.cpp
	g++ -std=c++11 $(CXXFLAGS) -c $^ -o $@

$(LIB_NAME): cosmix.o jsoncpp.o
	g++ -std=c++11 $(CXXFLAGS) $(LDFLAGS) $^ -o $@

clean:
	rm -f $(LIB_NAME) cosmix.o jsoncpp.o

