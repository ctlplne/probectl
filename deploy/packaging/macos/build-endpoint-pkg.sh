#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage: bash build-endpoint-pkg.sh --binary FILE --version X.Y.Z --output FILE.pkg
    --application-identity 'Developer ID Application: …'
    --installer-identity 'Developer ID Installer: …'
    or --test-unsigned for an unsigned local fixture
EOF
}

binary= version= output= application_identity= installer_identity= test_unsigned=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --test-unsigned) test_unsigned=true; shift ;;
        --binary|--version|--output|--application-identity|--installer-identity)
            if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then usage; exit 2; fi
            case "$1" in
                --binary) binary=$2 ;;
                --version) version=${2#v} ;;
                --output) output=$2 ;;
                --application-identity) application_identity=$2 ;;
                --installer-identity) installer_identity=$2 ;;
            esac
            shift 2
            ;;
        --help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

if [[ ! -f "$binary" || ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ || "$output" != *.pkg ]]; then
    usage
    exit 2
fi
if "$test_unsigned"; then
    if [[ -n "$application_identity" || -n "$installer_identity" ]]; then usage; exit 2; fi
elif [[ "$application_identity" != "Developer ID Application: "* || "$installer_identity" != "Developer ID Installer: "* ]]; then
    usage
    exit 2
fi
if [[ $(uname -s) != Darwin ]]; then
    echo 'The endpoint package requires macOS packaging tools.' >&2
    exit 1
fi

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/../../.." && pwd -P)
mkdir -p "$(dirname "$output")"
output_dir=$(cd "$(dirname "$output")" && pwd -P)
output="$output_dir/$(basename "$output")"
if [[ -e "$output" || -L "$output" ]]; then
    echo 'The package output already exists.' >&2
    exit 1
fi

stage=$(mktemp -d "$output_dir/.probectl-endpoint-pkg.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
root="$stage/payload"
app="$root/Applications/probectl Endpoint.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" "$root/Library/LaunchAgents"
executable="$app/Contents/MacOS/probectl-endpoint"
install -m 755 "$binary" "$executable"
install -m 644 "$repo/LICENSE" "$app/Contents/Resources/LICENSE"
install -m 644 "$repo/NOTICE" "$app/Contents/Resources/NOTICE"
# Validate the staged executable that will be signed and installed. Every
# Mach-O slice of the packaged binary needs the native Wi-Fi collector.
if ! /usr/bin/otool -arch all -L "$executable" | awk '
    /:$/ { if (seen && !corewlan) exit 1; seen=1; corewlan=0 }
    /\/CoreWLAN\.framework\// { corewlan=1 }
    END { if (!seen || !corewlan) exit 1 }
'; then
    echo 'Build the macOS endpoint with CGO_ENABLED=1 and the CoreWLAN framework.' >&2
    exit 1
fi
install -m 644 "$here/Endpoint-Info.plist" "$app/Contents/Info.plist"
install -m 644 "$here/com.probectl.endpoint.plist" "$root/Library/LaunchAgents/com.probectl.endpoint.plist"
/usr/bin/plutil -replace CFBundleShortVersionString -string "$version" "$app/Contents/Info.plist"
/usr/bin/plutil -replace CFBundleVersion -string "$version" "$app/Contents/Info.plist"
/usr/bin/plutil -lint "$app/Contents/Info.plist" "$here/components.plist" "$root/Library/LaunchAgents/com.probectl.endpoint.plist"

package_options=(--root "$root" --component-plist "$here/components.plist" --install-location /
    --identifier com.probectl.endpoint.pkg --version "$version" --ownership recommended)
if ! "$test_unsigned"; then
    /usr/bin/codesign --force --options runtime --timestamp --sign "$application_identity" "$app"
    /usr/bin/codesign --verify --strict "$app"
    package_options+=(--sign "$installer_identity")
fi

/usr/bin/pkgbuild "${package_options[@]}" "$stage/endpoint.pkg"
if ! "$test_unsigned"; then
    /usr/sbin/pkgutil --check-signature "$stage/endpoint.pkg"
fi
# The hard link publishes the completed archive without replacing another
# output. BSD ln can interpret an existing directory as a destination folder.
/bin/ln -h "$stage/endpoint.pkg" "$output"
if [[ -L "$output" || ! -f "$output" || ! "$output" -ef "$stage/endpoint.pkg" ]]; then
    if [[ -d "$output" && ! -L "$output" && "$output/endpoint.pkg" -ef "$stage/endpoint.pkg" ]]; then
        rm -- "$output/endpoint.pkg"
    fi
    echo 'The completed package could not be published at the requested file.' >&2
    exit 1
fi
printf 'Built %s\n' "$output"
