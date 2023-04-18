#!/bin/bash

# This script installs the Nix package manager on your system by
# downloading a binary distribution and running its installer script
# (which in turn creates and populates /nix).

{ # Prevent execution if this script was only partially downloaded
oops() {
    echo "$0:" "$@" >&2
    exit 1
}

umask 0022

tmpDir="$(mktemp -d -t nix-binary-tarball-unpack.XXXXXXXXXX || \
          oops "Can't create temporary directory for downloading the Nix binary tarball")"
cleanup() {
    rm -rf "$tmpDir"
}
trap cleanup EXIT INT QUIT TERM

require_util() {
    command -v "$1" > /dev/null 2>&1 ||
        oops "you do not have '$1' installed, which I need to $2"
}

case "$(uname -s).$(uname -m)" in
    Linux.x86_64)
        hash=1bdf98f951ce82ad1a12b9e6874f5858cb2aa2e402907e8c3079d8482cb8430b
        path=dw0gkcqnig9qwyhkrq0sjrzai63zi6wy/nix-2.15.0-x86_64-linux.tar.xz
        system=x86_64-linux
        ;;
    Linux.i?86)
        hash=c868bed9bfff72a363b1a41f95bce971f8ccca111e5e3c9f8e2fa5e9bde91f75
        path=ayl7z135hkqhf4px5pacv47b4njqb9yj/nix-2.15.0-i686-linux.tar.xz
        system=i686-linux
        ;;
    Linux.aarch64)
        hash=3a08669bf8d27b5994fceb2bc4653fddab189832a8bd111d013591862eb45961
        path=26zpxva102pm9jz8nkb391ws3c7six2j/nix-2.15.0-aarch64-linux.tar.xz
        system=aarch64-linux
        ;;
    Linux.armv6l)
        hash=88736c6fda47d2c244d38ec81250111263c6756a5c9e5232fb56d5e1245f3aae
        path=1m9il80f2y41qsarmarf3dkb23ryg2h8/nix-2.15.0-armv6l-linux.tar.xz
        system=armv6l-linux
        ;;
    Linux.armv7l)
        hash=44010bc59ad7504274533daf5d23d6773a286c5b7ac87960d330cc0580149462
        path=v2z7fhd4rq2n5s2svdk2dh6mf112w7ca/nix-2.15.0-armv7l-linux.tar.xz
        system=armv7l-linux
        ;;
    Darwin.x86_64)
        hash=d8b6a6e89f82113fcbce3d946fa501d5d2cf7cb35c88fb2017f3c12ef8392e7d
        path=m01jb6iyf73jiyzdn6vfap8da347nmwf/nix-2.15.0-x86_64-darwin.tar.xz
        system=x86_64-darwin
        ;;
    Darwin.arm64|Darwin.aarch64)
        hash=2d4a8060e12077f174e0635ec06d94daeee0460166165414698dfdf0ef87915a
        path=aa9fsy71mdsqp6kgf5sag6kv50zavhj5/nix-2.15.0-aarch64-darwin.tar.xz
        system=aarch64-darwin
        ;;
    *) oops "sorry, there is no binary distribution of Nix for your platform";;
esac

# Use this command-line option to fetch the tarballs using nar-serve or Cachix
if [ "${1:-}" = "--tarball-url-prefix" ]; then
    if [ -z "${2:-}" ]; then
        oops "missing argument for --tarball-url-prefix"
    fi
    url=${2}/${path}
    shift 2
else
    url=https://releases.nixos.org/nix/nix-2.15.0/nix-2.15.0-$system.tar.xz
fi

tarball=$tmpDir/nix-2.15.0-$system.tar.xz

require_util tar "unpack the binary tarball"
if [ "$(uname -s)" != "Darwin" ]; then
    require_util xz "unpack the binary tarball"
fi

if command -v curl > /dev/null 2>&1; then
    fetch() { curl --fail -L "$1" -o "$2"; }
elif command -v wget > /dev/null 2>&1; then
    fetch() { wget "$1" -O "$2"; }
else
    oops "you don't have wget or curl installed, which I need to download the binary tarball"
fi

echo "downloading Nix 2.15.0 binary tarball for $system from '$url' to '$tmpDir'..."
fetch "$url" "$tarball" || oops "failed to download '$url'"

if command -v sha256sum > /dev/null 2>&1; then
    hash2="$(sha256sum -b "$tarball" | cut -c1-64)"
elif command -v shasum > /dev/null 2>&1; then
    hash2="$(shasum -a 256 -b "$tarball" | cut -c1-64)"
elif command -v openssl > /dev/null 2>&1; then
    hash2="$(openssl dgst -r -sha256 "$tarball" | cut -c1-64)"
else
    oops "cannot verify the SHA-256 hash of '$url'; you need one of 'shasum', 'sha256sum', or 'openssl'"
fi

if [ "$hash" != "$hash2" ]; then
    oops "SHA-256 hash mismatch in '$url'; expected $hash, got $hash2"
fi

unpack=$tmpDir/unpack
mkdir -p "$unpack"
tar -xJf "$tarball" -C "$unpack" || oops "failed to unpack '$url'"

script=$(echo "$unpack"/*/install)

[ -e "$script" ] || oops "installation script is missing from the binary tarball!"
export INVOKED_FROM_INSTALL_IN=1
"$script" "$@"

} # End of wrapping
