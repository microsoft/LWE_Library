LWE Library
===========

This library implements Frodo, a lattice-based key exchange based on the Learning with Errors (LWE) problem.
The library uses Frodo's "recommended parameters". See [1] for details.

The library was developed by Microsoft Research for experimentation purposes.

Building and Running
--------------------

On Windows, the library builds with Visual Studio 2015, using the solution file (frodo.sln) in the "VisualStudio" folder. It has been tested with Windows 10.
On Linux, the library builds with GNU GCC or clang. It has been tested on Ubuntu 16.04 using GNU GCC version 5.4, and clang 3.8.

### Linux

To build, type with the following options:

$ make ARCH=[x64/x86/ARM] CC=[gcc/clang] USE_REFERENCE=[TRUE/FALSE] USE_AVX2=[TRUE/FALSE] AES_NI=[TRUE/FALSE]

When simply typing:

$make

the library is built using ARCH=x64, CC=gcc, USE_REFERENCE=FALSE, USE_AVX2=TRUE and AES_NI=TRUE, by default.

Building generates:

- `libfrodo.a`: a static library based on Frodo.
- `test_aes`: a test harness for AES.
- `test_rand`: a test harness for the random number generator.
- `test_kex`: a test harness for Frodo. 

To run the tests for Frodo, simply type:

$ ./test_kex

License
-------

The library is licensed under the MIT License. Part of the implementation is based on liboqs, also released under MIT. 
The library includes third party modules which have been released as public domain. Specifically:

- `src/aes/aes.c`: public domain
- `src/aes/aes_c.c`: public domain
- `src/aes/aes_ni.c`: public domain
- `src/sha3/fips202.c`: public domain
- `src/sha3/fips202x4.c`: public domain

Reference
---------
[1] Joppe W. Bos, Craig Costello, Leo Ducas, Ilya Mironov, Michael Naehrig, Valeria Nikolaenko, Ananth Raghunathan, and Douglas Stebila, "Frodo: Take off the Ring! Practical, Quantum-Secure Key Exchange from LWE".
ACM CCS 2016, 2016. The extended version is available at: https://eprint.iacr.org/2016/659.

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
