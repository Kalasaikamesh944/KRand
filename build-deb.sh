#!/bin/bash

# Package details
PKG_NAME="krand-dev"
VERSION="1.0.0"  # Change this for updates
ARCH="amd64"
MAINTAINER="Your Name <your@email.com>"
DESCRIPTION="KRand Development Library for Kali Linux"

# Build and package directories
BUILD_DIR="./${PKG_NAME}-${VERSION}"
DEBIAN_DIR="${BUILD_DIR}/DEBIAN"
USR_LOCAL_INCLUDE="${BUILD_DIR}/usr/local/include"
USR_LOCAL_LIB="${BUILD_DIR}/usr/local/lib"

# Cleanup previous build
rm -rf "${BUILD_DIR}" *.deb libKRand.a

# Ensure dependencies are installed
echo "🔍 Checking for required dependencies..."
sudo apt update
sudo apt install -y g++ make ar libssl-dev libpcap-dev libcurl4-openssl-dev

# Compile libKRand.a
echo "🔧 Compiling libKRand.a..."
g++ -c KRand.cpp -o KRand.o -I/usr/local/include
ar rcs libKRand.a KRand.o

# Create required directories
mkdir -p "${DEBIAN_DIR}" "${USR_LOCAL_INCLUDE}" "${USR_LOCAL_LIB}"

# Copy headers and compiled library
cp KRand.h "${USR_LOCAL_INCLUDE}/"
cp libKRand.a "${USR_LOCAL_LIB}/"

# Create control file
cat <<EOF > "${DEBIAN_DIR}/control"
Package: ${PKG_NAME}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: ${MAINTAINER}
Description: ${DESCRIPTION}
Depends: libssl-dev, libpcap-dev, libcurl4-openssl-dev
EOF

# Set permissions
chmod 0755 "${DEBIAN_DIR}"
chmod 0644 "${USR_LOCAL_INCLUDE}/KRand.h" "${USR_LOCAL_LIB}/libKRand.a"

# Build the package
dpkg-deb --build "${BUILD_DIR}"

# Rename the package
mv "${BUILD_DIR}.deb" "${PKG_NAME}-${VERSION}.deb"

echo "✅ Package ${PKG_NAME}-${VERSION}.deb created successfully!"
