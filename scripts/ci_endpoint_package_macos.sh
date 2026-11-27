#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

set -euo pipefail
umask 077
[[ ${RUNNER_ENVIRONMENT:-} == github-hosted && -n ${RUNNER_TEMP:-} ]]

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
work=$(mktemp -d "$RUNNER_TEMP/probectl-endpoint-XXXXXX")
keychain="$work/fixture.keychain-db"
root="$work/root.pem"
app_label="probectl macOS app fixture"
installer_label="probectl macOS installer fixture"
cleanup() {
    /usr/bin/security delete-keychain "$keychain" >/dev/null 2>&1 || true
    rm -rf -- "$work"
}
trap cleanup EXIT

bash "$repo/deploy/packaging/macos/build-endpoint-pkg.sh" \
    --binary "$1" --version 0.0.1 --output "$work/native.pkg" --test-unsigned
/usr/sbin/pkgutil --expand-full "$work/native.pkg" "$work/expanded"
payload="$work/expanded/Payload"
app="$payload/Applications/probectl Endpoint.app"
[[ -x "$app/Contents/MacOS/probectl-endpoint" ]]
[[ -f "$payload/Library/LaunchAgents/com.probectl.endpoint.plist" ]]

cat > "$work/cert.cnf" <<'EOF'
[req]
distinguished_name = subject
[subject]
[root]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
[application]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = codeSigning
[installer]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
# Apple's installer package signing purpose. This identity is locally issued.
extendedKeyUsage = 1.2.840.113635.100.4.13
EOF
/usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 1 -config "$work/cert.cnf" \
    -extensions root -subj "/CN=probectl macOS fixture authority" -keyout "$work/root.key" -out "$root"
password=$(/usr/bin/openssl rand -hex 24)
make_identity() {
    local purpose="$1" label="$2"
    /usr/bin/openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$label" \
        -keyout "$work/$purpose.key" -out "$work/$purpose.csr"
    /usr/bin/openssl x509 -req -in "$work/$purpose.csr" -CA "$root" -CAkey "$work/root.key" -CAcreateserial \
        -extfile "$work/cert.cnf" -extensions "$purpose" -days 1 -out "$work/$purpose.pem"
    /usr/bin/openssl pkcs12 -export -inkey "$work/$purpose.key" -in "$work/$purpose.pem" \
        -out "$work/$purpose.p12" -passout "pass:$password"
}
make_identity application "$app_label"
make_identity installer "$installer_label"
printf '%s\n' "Installing the test authority on the disposable runner"
sudo -n /usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$root"
printf '%s\n' "Importing the app and package test identity"
/usr/bin/security create-keychain -p "$password" "$keychain"
/usr/bin/security set-keychain-settings -lut 900 "$keychain"
/usr/bin/security unlock-keychain -p "$password" "$keychain"
/usr/bin/security import "$root" -k "$keychain"
/usr/bin/security import "$work/application.p12" -k "$keychain" -P "$password" -t cert -f pkcs12 -T /usr/bin/codesign
/usr/bin/security import "$work/installer.p12" -k "$keychain" -P "$password" -t cert -f pkcs12 -T /usr/bin/pkgbuild
/usr/bin/security list-keychains -d user -s "$keychain"
/usr/bin/security set-key-partition-list -S apple-tool:,apple: -s -k "$password" "$keychain" >/dev/null

signer=$(/usr/bin/openssl x509 -in "$work/application.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)
/usr/bin/security find-identity -v -p codesigning "$keychain" | /usr/bin/grep -Fi "$signer"
printf '%s\n' "Signing the app payload"
/usr/bin/codesign --force --options runtime --timestamp=none --keychain "$keychain" --sign "$signer" "$app"
printf '%s\n' "Signing the installer and verifying the complete package"
/usr/bin/pkgbuild --root "$payload" --component-plist "$repo/deploy/packaging/macos/components.plist" \
    --identifier com.probectl.endpoint.pkg --version 0.0.1 --install-location / --ownership recommended \
    --timestamp=none --keychain "$keychain" --sign "$installer_label" "$work/fixture.pkg"
/usr/sbin/pkgutil --check-signature "$work/fixture.pkg" | /usr/bin/grep -F "$installer_label"
/usr/sbin/pkgutil --expand-full "$work/fixture.pkg" "$work/verified"
/usr/bin/codesign --verify --strict -R="certificate leaf[subject.CN] = \"$app_label\"" \
    "$work/verified/Payload/Applications/probectl Endpoint.app"
