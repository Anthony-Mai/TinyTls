# TinyTls A Light Weight TLS Cryptography Library Written in C/C++

The TinyTls library is a lightweight TLS library written in C/C++ and is targeted
for embedded, RTOS, and other resource-constrained environments.
TinyTls supports TLS 1.2 (RFC5346) and the latest TLS 1.3 (RFC8446) as well, and
it is not only more elegant, but MUCH smaller than OpenSSL. TinyTls offers only
preferred ciphers such as AES128-GCM and ChaCha20-Poly1305, but get rid of rare
ciphers that few people use. And finally here is a TLS library written in C++
while OpenSsl and most other cryptographic libraries are still written in C.

TinyTls is self contained. It does not use any third party cryptographic library.
However you can easily plug in any third party crypto libraries that provide the
equivalent functionalities, but maybe you like better in some certain aspects.

TinyTls is meant to provide a good alternative to OpenSSL. So if you have good
suggestion on how to make it better, I would like to hear it. You can reach
the author at Mai_Anthony@hotmail.com.

## Why I developed TinyTls?
It is estimated that 70% of the world's securely connected devices use OpenSSL.
A lot of people don't like OpenSSL because it is very bulky, poorly maintained,
and contains too many legacy baggages. It is especially painful to use on some
resource constraint platforms. And the library is still written in C today.

But people really do not have a choice up till now. There was simply no good
light weight open source TLS library written in C++ and supports the TLS 1.3.
I want to demonstrate that a good light weight crypto library can be written
in C++ and can be made more maintainable. TinyTls was once based on TinySsl,
but I have re-written a lot of new code and get rid of legacy stuffs that are
no longer relevant today. So there is no historic baggage in the package.

***

# Notes - Please read

## Note 1
```
TinyTls supports only TLS 1.2 and TLS 1.3. I see no point continue to support
TLS 1.0. It was just so old and obsolete. Why would any one still use TLS 1.0
today if security even matters at all. Further, TinyTls supports only two
symmetric ciphers: AES128-GCM, and ChaCha20-Poly1305.

TinyTls supports both RSA and Elliptic Curve Cryptography. Only 2048 bits RSA
keys are supported because every one mostly uses only 2048 bits. The only ECC
curve groups used are X25519 and secp256r1, as anything else are rarely used.
```

# How to Build

## Build on Linux
```
TinyTls uses cmake to create make files to build. Please install cmake if you
have not already done some. Once you have cmake, follow these steps:

1. Under the main directory of TinyTls, create a subdirectory called build,
   and change directory to there:
    mkdir -p build; cd build

2. Run the cmake command to configure build files:
   (the .. tells cmake to go up one level to find the CMakeList.txt file)
    cmake ..

3. Run the make command:
    make -j8

You may have to run the same make command a few more times, if it fails to
build all dependencies in just one pass. Please help if you can fix this.

The Linux make file will try to cross build both 32 bits and 64 bits binary.
You may run into compile errors like this when <stdint.h> is first included:
  /usr/include/stdint.h:26:10: fatal error: bits/libc-header-start.h: No such file or directory
or
  /usr/include/c++/7/new:39:10: fatal error: bits/c++config.h: No such file or directory

The solution is rather easy. Just install the needed gcc multi-arch packages:
  sudo apt-get install gcc-multilib g++-multilib

Read related online discussions here on stackoverflow.com:
  https://stackoverflow.com/questions/54082459/fatal-error-bits-libc-header-start-h-no-such-file-or-directory-while-compili
  https://stackoverflow.com/questions/4643197/missing-include-bits-cconfig-h-when-cross-compiling-64-bit-program-on-32-bit

Note on Raspberry Pi 3 b+: The processor on Raspberry Pi 3B+ is an ARMV7l
processor. Unfortunately the default GCC that comes with Raspian is
GCC-4.6 which would only produce ARMV6 xexcutables, and it cannot be
made tp produce armv7 executables. To enjoy the full feature of ARMv7
you must upgrade to GCC-4.8. Follow instructions here on how to do it:
    http://www.raspberryvi.org/stories/upgrade-gcc-armv7.html

Similarly on Aarch64 platforms, like Nano Pi containing a Rockchip3399
processor, the default compiler many not be able to leverage advanced
features of armv8. Follow instructions at above web site to tweak the
compile commands. Specifically remove these symbolic links (but before
that make sure you note down what were the original symbolic links):
    /usr/bin/gcc /usr/bin/g++ /usr/bin/as
Then replace these three symbolic links with real script files that
refer to the actual commands meant to be executed. I used these:

My /usr/bin/gcc looks like this:
#!/bin/bash
gcc-7 $* -march=armv8-a

My /usr/bin/g++ looks like this:
#!/bin/bash
g++-7 $* -march=armv8-a

My /usr/bin/as looks like this:
#!/bin/bash
aarch64-linux-gnu-as $* -march=armv8-a+crypt

Finally do not forget to chmod 0755 to allow them to be executed.

```

# TinyTls Release 1.0.0 (03/24/2019)

This is the inauguration release of TinyTls. Features including:

* Supports both TLS 1.2 and TLS 1.3
* One simple library is used to build both a client and a server.
* Include code for X.509 digital certificate issuance/generation.

# Resources

[TLS 1.2](https://tools.ietf.org/html/rfc5246)
[TLS 1.3](https://tools.ietf.org/html/rfc8446)
