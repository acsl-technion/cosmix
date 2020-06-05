# Use an official runtime as a parent image
FROM ubuntu:16.04

# Stop script if any individual command fails.
RUN set -e

# Define LLVM version.
ENV llvm_version=6.0.0

# Define dependencies.
ENV lib_deps="make g++ git zlib1g-dev libncurses5-dev libssl-dev libpcre2-dev zip vim libevent-dev libcurl4-openssl-dev libprotobuf-dev"
ENV build_deps="wget xz-utils cmake python autoconf ocaml automake autoconf libtool protobuf-compiler debhelper"

# SVF ENV variables
ENV LLVM_DIR=/home/user/llvm
ENV PATH=${LLVM_DIR}/bin:${PATH}

# Fetch dependencies.
RUN apt-get update
RUN apt-get install -y $build_deps $lib_deps

RUN adduser cosmix-user

# Fetch LLVM+CLANG
WORKDIR /home/user
RUN wget "http://releases.llvm.org/6.0.0/clang+llvm-6.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz"
RUN tar xvf "clang+llvm-6.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz"
RUN mv "clang+llvm-6.0.0-x86_64-linux-gnu-ubuntu-16.04" "llvm"
RUN rm "clang+llvm-6.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz"

# Fetch SGX SDK for SUVM mstore
WORKDIR /home/user
RUN mkdir -p dev
WORKDIR /home/user/dev
RUN wget "https://download.01.org/intel-sgx/linux-2.6/ubuntu16.04-server/sgx_linux_x64_sdk_2.6.100.51363.bin"
RUN echo "no" > temp && echo "/home/user/dev" >> temp
RUN mkdir -p /home/user/dev/sgxsdk
RUN chmod +x ./sgx_linux_x64_sdk_2.6.100.51363.bin
RUN ./sgx_linux_x64_sdk_2.6.100.51363.bin < temp

# Fetch COSMIX
WORKDIR /home/user/dev
RUN git clone "https://github.com/acsl-technion/cosmix"
WORKDIR /home/user/dev/cosmix

# Build SVF
RUN git submodule update --init
WORKDIR /home/user/dev/cosmix/SVF
RUN git checkout SVF-1.5
RUN sed -i '2i\set(CMAKE_POSITION_INDEPENDENT_CODE ON)' CMakeLists.txt
RUN mkdir Release-build
WORKDIR /home/user/dev/cosmix/SVF/Release-build
RUN cmake ../
RUN make -j4

# Build CoSMIX
WORKDIR /home/user/dev/cosmix
RUN sed -i 's/\/opt\/intel/\/home\/user\/dev/g' Defines.mk
RUN make

RUN echo "COSMIX image constructed succesfully, to enter image run"
RUN echo "docker run -it cosmix /bin/bash"

RUN echo ".2" > /dev/null && git pull
