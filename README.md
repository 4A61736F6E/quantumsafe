
# IBM Research

This work is based on the information and instructions taken from the IBM article [Developing with quantum-safe OpenSSL](https://developer.ibm.com/tutorials/awb-quantum-safe-openssl/).  The goal was to _follow along_ to understand the build process, dependencies, and how to interface with quantum-safe algorithms.  Good news, it worked!  But not without a few hiccups along the way.

While the article shows you commands to execute, there were a number of problems observed with the syntax.
- Hidden characters abound in most of the command samples.
- Missing characters (`BUILDDIR` instead of `$BUILD_DIR`)
- Replaced characters (hyphen versues HTTP dash)
- Or garbled syntax (`BUILDDIR/bin/curl−vkhttps://test.openquantumsafe.org/CA.crt−−output...`)

While the instructions do allude to pinning specific versions of software to a particular software releases in the respective repositories.  Those are noted with comments of `IBM OPTIONAL` to preserve the original work by the researchers.  

When working through this myself, I pinned the software versions as well as follows, and also noted as a comment denoting the version along with the respective `git checkout` command.  The instructions below assume the following software versions:
- `openssl` version 3.4.0
- `liboqs` version 0.12.0
- `oqs-provider` version 0.8.0
- `curl` version 8.11.1

It is strongly recommended to remain with official releases of the source code and avoid any development branches or release unless that is what you are signing up for.  Unkonwningly, I spent too much time problem solving against a -dev openssl release before pivoting to the official latest release of 3.4.0.

The following steps are based on the IBM article.

# Testing Environments
| Platform       | Arch    | Operating System               | Kernel |
|----------------|---------|--------------------------------|---------------------|
| Rasberry Pi 5  | aarch64 | Debian GNU/Linux 12 (bookworm) | 6.6.74+rpt-rpi-2712 |
| VMWare Fusion  | aarch64 | Ubuntu 24.04.1 LTS             | 6.8.0-52-generic |
| VMWare Fusion  | aarch64 | Kali Linux 2025.1              | 6.12.13-arm64 |
| Microsoft WSL2 | x86_64  | Ubuntu 24.04.1 LTS             | 5.15.167.4-microsoft-standard-WSL2 |
| Microsoft WSL2 | x86_64  | Kali Linux 2025.1              | 5.15.167.4-microsoft-standard-WSL2 |
| Amazon EC2     | x86_64  | Amazon Linux 2023              | 6.1.124-134.200.amzn2023.x86_64 |


# Steps

## Step 1. Install the dependencies

```shell
# Debian based OSes
sudo apt update
sudo apt -y install git build-essential perl cmake autoconf libtool zlib1g-dev

# RHEL based OSes
# sudo yum -y install git gcc gcc-c++ make perl cmake autoconf libtool zlib-devel

export WORKSPACE=~/quantumsafe    # set this to a working directory of your choice
export BUILD_DIR=$WORKSPACE/build # this will contain all the build artifacts
mkdir -p $BUILD_DIR/lib64
ln -s $BUILD_DIR/lib64 $BUILD_DIR/lib
```


## Step 2. Install OpenSSL

```shell
cd $WORKSPACE

git clone https://github.com/openssl/openssl.git
cd openssl

# IBM OPTIONAL:   git checkout c8ca810da9
# OpenSSL v3.4.0: git checkout 98acb6b

./Configure \
  --prefix=$BUILD_DIR \
  no-ssl no-tls1 no-tls1_1 no-afalgeng \
  no-shared threads -lm

make -j $(nproc); make -j $(nproc) install_sw install_ssldirs

$BUILD_DIR/bin/openssl version
#--- sample output
OpenSSL 3.4.0 22 Oct 2024 (Library: OpenSSL 3.4.0 22 Oct 2024)
```


## Step 3. Install liboqs

```shell
cd $WORKSPACE

git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# IBM OPTIONAL:   git checkout 78e65bf1
# liboqs v0.12.0: git checkout f4b9622

mkdir build && cd build

cmake \
  -DCMAKE_INSTALL_PREFIX=$BUILD_DIR \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_USE_OPENSSL=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_DIST_BUILD=ON \
  ..

make -j $(nproc); make -j $(nproc) install
```


## Step 4. Install Open Quantum Safe provider for OpenSSL 3

```shell
cd $WORKSPACE

git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider

# IBM OPTIONAL:        git checkout d540c28
# oqs-provider v0.8.0: git checkout ec1e843 

liboqs_DIR=$BUILD_DIR cmake \
  -DCMAKE_INSTALL_PREFIX=$WORKSPACE/oqs-provider \
  -DOPENSSL_ROOT_DIR=$BUILD_DIR \
  -DCMAKE_BUILD_TYPE=Release \
  -S . \
  -B _build

cmake --build _build

# Manually copy the lib files into the build dir
cp _build/lib/* $BUILD_DIR/lib/

# We need to edit the openssl config to use the oqsprovider
# This deviates slightly from IBM but yields the desired results, update to the .cnf file.
sed -i "s/default = default_sect/default = default_sect\noqsprovider = oqsprovider_sect\n/g" $BUILD_DIR/ssl/openssl.cnf

sed -i '/\[default_sect\]/ {
    N; s/# activate = 1/activate = 1/;
    a\
\n[oqsprovider_sect]\
activate = 1
}' $BUILD_DIR/ssl/openssl.cnf

# These env vars need to be set for the oqsprovider to be used when using OpenSSL
export OPENSSL_CONF=$BUILD_DIR/ssl/openssl.cnf
export OPENSSL_MODULES=$BUILD_DIR/lib

$BUILD_DIR/bin/openssl list -providers -verbose -provider oqsprovider

#--- sample output
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.4.0
    status: active
    build info: 3.4.0
    gettable provider parameters:
      name: pointer to a UTF8 encoded string (arbitrary size)
      version: pointer to a UTF8 encoded string (arbitrary size)
      buildinfo: pointer to a UTF8 encoded string (arbitrary size)
      status: integer (arbitrary size)
  oqsprovider
    name: OpenSSL OQS Provider
    version: 0.8.0
    status: active
    build info: OQS Provider v.0.8.0 (ec1e843) based on liboqs v.0.12.0
    gettable provider parameters:
      name: pointer to a UTF8 encoded string (arbitrary size)
      version: pointer to a UTF8 encoded string (arbitrary size)
      buildinfo: pointer to a UTF8 encoded string (arbitrary size)
      status: integer (arbitrary size)
```

The [oqs-provider scripts readme](https://github.com/open-quantum-safe/oqs-provider/blob/main/scripts/README.md) makes note of a `runtests.sh` script.  This takes a little time to execute but if you wish to be thorough with your testing, here you go.

```shell
export OPENSSL_INSTALL=$BUILD_DIR
cd $WORKSPACE/oqs-provider
scripts/runtests.sh

#--- sample output
Test setup:
LD_LIBRARY_PATH=/home/jason/quantumsafe/build/lib64
OPENSSL_APP=/home/jason/quantumsafe/build/bin/openssl
OPENSSL_CONF=/home/jason/quantumsafe/build/ssl/openssl.cnf
OPENSSL_MODULES=/home/jason/quantumsafe/build/lib
No OQS-OpenSSL111 interop test because of absence of docker
Version information:
OpenSSL 3.4.0 22 Oct 2024 (Library: OpenSSL 3.4.0 22 Oct 2024)
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.4.0
    status: active
    build info: 3.4.0
    gettable provider parameters:
      name: pointer to a UTF8 encoded string (arbitrary size)
      version: pointer to a UTF8 encoded string (arbitrary size)
      buildinfo: pointer to a UTF8 encoded string (arbitrary size)
      status: integer (arbitrary size)
  oqsprovider
    name: OpenSSL OQS Provider
    version: 0.8.0
    status: active
    build info: OQS Provider v.0.8.0 (ec1e843) based on liboqs v.0.12.0
    gettable provider parameters:
      name: pointer to a UTF8 encoded string (arbitrary size)
      version: pointer to a UTF8 encoded string (arbitrary size)
      buildinfo: pointer to a UTF8 encoded string (arbitrary size)
      status: integer (arbitrary size)
Cert gen/verify, CMS sign/verify, CA tests for all enabled OQS signature algorithms commencing:
.........................................................
External interop tests commencing
 Google:
  x25519_kyber768 @ oqsprovider
  X25519MLKEM768 @ oqsprovider
Test project /home/jason/quantumsafe/oqs-provider/_build
    Start 1: oqs_signatures
1/6 Test #1: oqs_signatures ...................   Passed   30.07 sec
    Start 2: oqs_kems
2/6 Test #2: oqs_kems .........................   Passed    2.23 sec
    Start 3: oqs_groups
3/6 Test #3: oqs_groups .......................   Passed    2.92 sec
    Start 4: oqs_tlssig
4/6 Test #4: oqs_tlssig .......................   Passed   17.08 sec
    Start 5: oqs_endecode
5/6 Test #5: oqs_endecode .....................   Passed   66.48 sec
    Start 6: oqs_evp_pkey_params
6/6 Test #6: oqs_evp_pkey_params ..............   Passed    6.80 sec

100% tests passed, 0 tests failed out of 6

Total Test time (real) = 125.59 sec

All oqsprovider tests passed.
```

You can also display the OpenSSL provider algorithms.

```shell
$BUILD_DIR/bin/openssl list -kem-algorithms -provider oqsprovider

#--- sample output
  { 1.2.840.113549.1.1.1, 2.5.8.1.1, RSA, rsaEncryption } @ default
  { 1.2.840.10045.2.1, EC, id-ecPublicKey } @ default
  { 1.3.101.110, X25519 } @ default
  { 1.3.101.111, X448 } @ default
  frodo640aes @ oqsprovider
  p256_frodo640aes @ oqsprovider
  x25519_frodo640aes @ oqsprovider
  frodo640shake @ oqsprovider
  p256_frodo640shake @ oqsprovider
  x25519_frodo640shake @ oqsprovider
  frodo976aes @ oqsprovider
  p384_frodo976aes @ oqsprovider
  x448_frodo976aes @ oqsprovider
  frodo976shake @ oqsprovider
  p384_frodo976shake @ oqsprovider
  x448_frodo976shake @ oqsprovider
  frodo1344aes @ oqsprovider
  p521_frodo1344aes @ oqsprovider
  frodo1344shake @ oqsprovider
  p521_frodo1344shake @ oqsprovider
  kyber512 @ oqsprovider
  p256_kyber512 @ oqsprovider
  x25519_kyber512 @ oqsprovider
  kyber768 @ oqsprovider
  p384_kyber768 @ oqsprovider
  x448_kyber768 @ oqsprovider
  x25519_kyber768 @ oqsprovider
  p256_kyber768 @ oqsprovider
  kyber1024 @ oqsprovider
  p521_kyber1024 @ oqsprovider
  mlkem512 @ oqsprovider
  p256_mlkem512 @ oqsprovider
  x25519_mlkem512 @ oqsprovider
  mlkem768 @ oqsprovider
  p384_mlkem768 @ oqsprovider
  x448_mlkem768 @ oqsprovider
  X25519MLKEM768 @ oqsprovider
  SecP256r1MLKEM768 @ oqsprovider
  mlkem1024 @ oqsprovider
  p521_mlkem1024 @ oqsprovider
  p384_mlkem1024 @ oqsprovider
  bikel1 @ oqsprovider
  p256_bikel1 @ oqsprovider
  x25519_bikel1 @ oqsprovider
  bikel3 @ oqsprovider
  p384_bikel3 @ oqsprovider
  x448_bikel3 @ oqsprovider
  bikel5 @ oqsprovider
  p521_bikel5 @ oqsprovider
  hqc128 @ oqsprovider
  p256_hqc128 @ oqsprovider
  x25519_hqc128 @ oqsprovider
  hqc192 @ oqsprovider
  p384_hqc192 @ oqsprovider
  x448_hqc192 @ oqsprovider
  hqc256 @ oqsprovider
  p521_hqc256 @ oqsprovider
```


## Step 5. Install and run cURL with quantum-safe algorithms


```shell
cd $WORKSPACE

git clone https://github.com/curl/curl.git
cd curl

# IBM OPTIONAL: git checkout 0eda1f6c9
# curl v8.11.1: git checkout 75a2079 

autoreconf -fi

./configure \
  LIBS="-lssl -lcrypto -lz" \
  LDFLAGS="-Wl,-rpath,$BUILD_DIR/lib64 -L$BUILD_DIR/lib64 -Wl,-rpath,$BUILD_DIR/lib -L$BUILD_DIR/lib" \
  CFLAGS="-O3 -fPIC" \
  --prefix=$BUILD_DIR \
  --with-ssl=$BUILD_DIR \
  --with-zlib=/ \
  --enable-optimize --enable-libcurl-option --enable-libgcc --enable-shared \
  --enable-ldap=no --enable-ipv6 --enable-versioned-symbols \
  --disable-manual \
  --without-default-ssl-backend \
  --without-librtmp --without-libidn2 \
  --without-gnutls --without-mbedtls \
  --without-wolfssl --without-libpsl

make -j $(nproc); make -j $(nproc) install

```

This next section deviates a little from IBM's instructions only in that additional test cases are available.  If you navigate to the [Open Quantum Safe Test Environment](https://test.openquantumsafe.org/), there is a table of signature algorithms, key exchange algorithms, port numbers, and URLs to test against.  There are _numerous_ options available.

```shell
# First, download the root CA.
$BUILD_DIR/bin/curl -vk https://test.openquantumsafe.org/CA.crt --output $BUILD_DIR/ca.cert

# Then play . . . 

# Client: p521_kyber1024, Connection: ecdsap256-p521_kyber1024
$BUILD_DIR/bin/curl --curves p521_kyber1024 --cacert $BUILD_DIR/ca.cert https://test.openquantumsafe.org:6041

# Client: p521_kyber1024, Connection: rsa3072-p521_kyber1024
$BUILD_DIR/bin/curl --curves p521_kyber1024 --cacert $BUILD_DIR/ca.cert https://test.openquantumsafe.org:6095

# Client: p521_kyber1024, Connection: dilithium5-p521_kyber1024
$BUILD_DIR/bin/curl --curves p521_kyber1024 --cacert $BUILD_DIR/ca.cert https://test.openquantumsafe.org:6185


# Client: p521_mlkem1024, Connection: ecdsap256-p521_mlkem1024
$BUILD_DIR/bin/curl --curves p521_mlkem1024 --cacert $BUILD_DIR/ca.cert https://test.openquantumsafe.org:6049

# Client: p521_mlkem1024, Connection: rsa3072-p521_kyber1024
$BUILD_DIR/bin/curl --curves p521_mlkem1024 --cacert $BUILD_DIR/ca.cert https://test.openquantumsafe.org:6103

# Client: p521_mlkem1024, Connection: dilithium5-p521_kyber1024
$BUILD_DIR/bin/curl --curves p521_mlkem1024 --cacert $BUILD_DIR/ca.cert https://test.openquantumsafe.org:6186
```

If you are attached to an enterprise network, the use of the obscure port numbers by this web site may be prohibited.  Below is an example of blocked access to port `6041/tcp`.

```shell
$ $BUILD_DIR/bin/curl --curves p521_kyber1024 --cacert $BUILD_DIR/ca.cert https://test.openquantumsafe.org:6041
curl: (35) Recv failure: Connection reset by peer
```