# COSMIX
COSMIX is an LLVM pass, coupled with a runtime and different Memory stores (Mstores) which intends to provide enclaves with trusted, efficient, and customizable page fault handlers.
For more information, please refer the following paper:
["CoSMIX: A Compiler-based System for Secure Memory Instrumentation and Execution in Enclaves"](https://www.usenix.org/conference/atc19/presentation/orenbach).

## Components

* [`Compiler pass`](pass/) - CoSMIX LLVM Module pass.
* [`Runtime/`](runtime/) - CoSMIX Runtime.
* [`Memory stores/`](mstores/) - Example of three different memory stores, and common building blocks they all use internally.
* [`Samples/`](samples/) - Applications of different flavours using CoSMIX, with Makefile examples of the different compilation and customization options.
* [`Configuration/`](config_files/) - Memory stores sample configuration files.

## Building
CoSMIX build was tested on Ubuntu 16.04 and Ubuntu 18.04 with LLVM 6.0.0.
CoSMIX can be used in enclaves and also in regular applications.

### Dependencies
* [`LLVM 6.0.0`](http://releases.llvm.org/download.html)
* [`Clang 6.0.0`](http://releases.llvm.org/download.html)
* [`SVF 1.5`](https://github.com/SVF-tools/SVF)

To use CoSMIX with SGX enclaves, the following are also required:
* [`SGX supported hardware`](https://github.com/ayeks/SGX-hardware)
* [`Intel SGX Driver`](https://github.com/intel/linux-sgx-driver)
* [`Intel SGX SDK`](https://github.com/intel/linux-sgx). This is needed only by the SUVM Mstore.

CoSMIX requires setting the installed dependencies paths in the [`Defines.mk`](Defines.mk) file.
Building is then as simple as:
```shell
git submodule update --init
cd SVF
git checkout SVF-1.5
sed -i '2i\set(CMAKE_POSITION_INDEPENDENT_CODE ON)' CMakeLists.txt
export LLVM_DIR=<llvm installed path>
export PATH=$LLVM_DIR/bin:$PATH
mkdir Release-build
cd Release-build
cmake ../
make -j4
cd ../
make
```

### Samples
It is possible to validate CoSMIX was installed and works as expected by running a small validation suite that uses the SUVM mstore.
```shell
cd validation/regression
./run_validation_suite.sh 
```

We provide different sample applications under the samples/ directory with example Makefiles with the different CoSMIX compilation flags, which may be customized.
CoSMIX expects a whole program bitcode file to operate on as it is implemented as an LLVM Module pass. To that end, LLVM Gold Plugin, a link-time optimizer can generate whole program bit code files.

### Run CoSMIX inside a contianer
```shell
docker build -t "cosmix" .
docker run -it cosmix /bin/bash
```

### Running applications compiled by CoSMIX in enclaves
CoSMIX can be used with a Library Operating System (LibOS) that allows running unmodified applications inside SGX enclaves.
Examples of such tools are: Graphene-SGX, Anjuna and SCONE. 
* [`Graphene-SGX`](https://github.com/oscarlab/graphene) is an open source LibOS. To run applications with mstore support inside SGX enclaves with the help of Graphene-SGX follow the instruction provided in Graphene-SGX documents.
Note, the SUVM mstore manages evicted pages in untrusted memory. Therefore, to run applications with SUVM mstore support inside Graphene-SGX, we modified Graphene-SGX and added a new
untrusted memory allocation system call, which is exposed directly to applications executing inside Graphene-SGX enclaves.
[`Modified Graphene-SGX code`](https://github.com/acsl-technion/graphene/tree/untrusted_alloc)
Note, using the modified Graphene-SGX code is at your own risk.
* [`Intel SGX SDK`](https://github.com/intel/linux-sgx) is an open source SGX enclave framework by Intel. It allows partitioning applications into trusted and untrusted components,
where the trusted code and data are executed and accessed inside an enclave. To run such enclaves with mstore support please refer to
[`the SGX SDK samples directory`](sgxsdk_samples/) for example use cases.

## License
CoSMIX is licensed under the BSD 2-Clause License. Please refer to the `LICENSE.txt` file for more details.

## Contributions and Support
CoSMIX welcomes contributions and suggestions.
CoSMIX is a research prototype; therefore, while we try our best to resolve issues as fast as possible, support is currently limited.

### Adding a new Memory store
Sources for example memory stores are availabe under the mstores/ directory. As a reference you may look at
mstores/suvm for cached memory store implementation and
mstores/oram for direct access memory store implementation.
Please note of the function naming conventions used, as this is the contract the compiler pass looks for to auto-generate the callbacks
in the CoSMIX runtime.

### Adding new wrapper to libc function
Please refer to the sources under runtime/ directory.

We release CoSMIX source code in the hope of benefiting others. You are kindly asked to acknowledge usage by citing the CoSMIX paper.
<details>
  <summary>BibTeX</summary>

    @inproceedings {cosmix::atc19,
    author = {Meni Orenbach and Yan Michalevsky and Christof Fetzer and Mark Silberstein},
    title = {CoSMIX: A Compiler-based System for Secure Memory Instrumentation and Execution in Enclaves},
    booktitle = {2019 {USENIX} Annual Technical Conference ({USENIX} {ATC} 19)},
    year = {2019},
    address = {Renton, WA},
    url = {https://www.usenix.org/conference/atc19/presentation/orenbach},
    publisher = {{USENIX} Association},
    }

</details>
