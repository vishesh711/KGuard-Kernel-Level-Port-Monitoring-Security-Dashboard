#!/usr/bin/env bash
#
# Build and test the module on several kernel versions (roadmap P8.5).
#
# For each version, fetch the Ubuntu mainline build (image, modules,
# headers) from kernel.ubuntu.com, build kguard.ko against those headers
# with warnings as errors, boot that kernel in a throwaway VM
# (run_in_vm.sh, virtme-ng) and run the full kernel suite there.
#
# Usage: kernel/tests/kernel_matrix.sh [VERSION...]
#   default versions: the LTS series 5.15, 6.1, 6.6, 6.12 and the latest
#   stable, each at its newest point release.
#   KERNEL_CACHE=dir   where packages are kept (default ~/.cache/kguard-kernels)
#   BUILD_ONLY=1       build against each kernel, boot nothing
#
# Needs root (it links each kernel's modules into /lib/modules for the VM),
# curl, dpkg-deb, virtme-ng and qemu. Uses KVM when /dev/kvm exists.

set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p tests/out
MAINLINE=https://kernel.ubuntu.com/mainline
CACHE="${KERNEL_CACHE:-$HOME/.cache/kguard-kernels}"
SERIES=("$@")
[[ ${#SERIES[@]} -gt 0 ]] || SERIES=(5.15 6.1 6.6 6.12 latest)

index=$(curl -fsSL --retry 3 "$MAINLINE/")

newest() {  # newest point release of a series, e.g. 6.1 -> v6.1.192
    if [[ "$1" == latest ]]; then
        grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+/' <<<"$index" | grep -v -- '-rc' | sort -uV | tail -1 | tr -d /
    elif [[ "$1" == v* ]]; then
        echo "$1"
    else
        grep -oE "v${1//./\\.}\.[0-9]+/" <<<"$index" | sort -uV | tail -1 | tr -d /
    fi
}

fetch() {  # download and unpack one version's packages; prints the vmlinuz path
    local version=$1 dir="$CACHE/$1"
    mkdir -p "$dir/debs" "$dir/root"
    if [[ ! -f "$dir/unpacked" ]]; then
        local files
        files=$(curl -fsSL --retry 3 "$MAINLINE/$version/amd64/" |
                grep -oE 'href="linux-(headers|image-unsigned|modules)-[^"]+(_all|_amd64)\.deb"' |
                sed 's/^href="//; s/"$//' | grep -v -- '-lowlatency')
        [[ -n "$files" ]] || { echo "no amd64 packages for $version" >&2; return 1; }
        for f in $files; do
            [[ -f "$dir/debs/$f" ]] || curl -fsSL --retry 3 -o "$dir/debs/$f" "$MAINLINE/$version/amd64/$f"
            dpkg-deb -x "$dir/debs/$f" "$dir/root"
        done
        touch "$dir/unpacked"
    fi
    ls "$dir"/root/boot/vmlinuz-* | head -1
}

results=()
status=0
for series in "${SERIES[@]}"; do
    version=$(newest "$series")
    echo "== $series: $version"
    if ! image=$(fetch "$version"); then
        results+=("$version  download failed")
        status=1
        continue
    fi
    kver=$(basename "$image" | sed 's/^vmlinuz-//')
    root="$CACHE/$version/root"
    # The VM uses the host's /lib/modules for that kernel's modules (conntrack, nf_socket)
    ln -sfn "$root/lib/modules/$kver" "/lib/modules/$kver"
    kdir="$root/usr/src/linux-headers-$kver"

    # Build with the kernel's own compiler when installed, else the newest gcc here
    # (mainline builds of recent kernels use a gcc newer than this distribution has)
    kcc=$(sed -n 's/^CONFIG_CC_VERSION_TEXT="\(x86_64-linux-gnu-\)\{0,1\}\(gcc[-0-9]*\) .*/\2/p' "$kdir/.config")
    if ! command -v "${kcc:-gcc}" >/dev/null; then
        newest=$(compgen -c gcc- | grep -E '^gcc-[0-9]+$' | sort -t- -k2 -n | tail -1)
        echo "  $kcc is not installed: building with ${newest:-gcc} instead"
        kcc=${newest:-gcc}
        # The kernel's config enables attributes (counted_by) only its own compiler knows;
        # an older one warns about them in the kernel's headers. Keep those as warnings.
        export KCFLAGS="-Wno-error=attributes"
    else
        unset KCFLAGS
    fi
    make KDIR="$kdir" clean >/dev/null
    if ! make KDIR="$kdir" CC="$kcc" > "tests/out/build-$version.log" 2>&1; then
        echo "build failed:"; grep -E "error|warning" "tests/out/build-$version.log" | head -20
        results+=("$version  BUILD FAILED")
        status=1
        continue
    fi
    if [[ -n "${BUILD_ONLY:-}" ]]; then
        results+=("$version  builds")
        continue
    fi
    if out=$(KDIR="$kdir" CC="$kcc" tests/run_in_vm.sh "$image" 2>&1); then
        results+=("$version  $(tail -1 <<<"$out")")
    else
        echo "$out" | grep -E '^FAIL|did not finish' | head -20
        results+=("$version  FAILED: $(tail -1 <<<"$out")")
        status=1
    fi
done

echo
echo "Kernel matrix:"
printf '  %s\n' "${results[@]}"
exit $status
