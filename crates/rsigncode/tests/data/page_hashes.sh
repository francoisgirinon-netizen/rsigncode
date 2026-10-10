#!/bin/sh
# Produces tests/data/page_hashes.txt: the page hash tables that osslsigncode embeds in the
# SpcPeImageData of the signature when it signs with -ph. The tables are the oracle of the
# page hash tests (tests/pe_page_hashes.rs). Nothing here uses rsigncode.
#
# Usage: page_hashes.sh <osslsigncode> <fixture-dir> > page_hashes.txt
#
#   cargo run --example fixtures -- <fixture-dir>      # writes the *.exe fixtures
#   page_hashes.sh /path/to/osslsigncode <fixture-dir> > crates/rsigncode/tests/data/page_hashes.txt
#
# Needs openssl. A fixture that osslsigncode refuses gives "<name> <alg> error: <message>".
# Output: one line per (fixture, algorithm): "<name> <sha1|sha256> <hex>",
# where <hex> is the content of the OCTET STRING in the SpcAttributeTypeAndOptionalValue
# whose type is 1.3.6.1.4.1.311.2.3.1 (SHA-1) or 1.3.6.1.4.1.311.2.3.2 (SHA-256): the
# table of (u32 LE file offset, digest) entries followed by the terminating entry.
set -eu
ossl=$1
dir=$2
work=$(mktemp -d "${TMPDIR:-/tmp}/ph.XXXXXX")
trap 'rm -rf "$work"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/k.pem" -out "$work/c.pem" \
    -subj /CN=test -days 3650 2>/dev/null
here=$(cd "$(dirname "$0")" && pwd)
for f in "$dir"/ph_*.exe "$dir"/pe32_aligned.exe "$dir"/pe64_aligned.exe \
    "$dir"/pe32_extra_3.exe "$here"/tiny32.efi "$here"/tiny64.efi; do
    name=$(basename "$f")
    name=${name%.*}
    for alg in sha1 sha256; do
        rm -f "$work/s.exe" "$work/s.der"
        if ! "$ossl" sign -certs "$work/c.pem" -key "$work/k.pem" -h "$alg" -ph \
            -in "$f" -out "$work/s.exe" >"$work/log" 2>&1; then
            # The oracle refuses the file (e.g. headers larger than a page): record it.
            echo "$name $alg error: $(grep -m1 -i 'size\|fail' "$work/log")"
            continue
        fi
        "$ossl" extract-signature -in "$work/s.exe" -out "$work/s.der" >/dev/null
        # The page hash attribute is the OCTET STRING that starts with a SET (0x31).
        off=$(openssl asn1parse -inform DER -in "$work/s.der" |
            grep 'OCTET STRING.*HEX DUMP\]:31' | head -1 | cut -d: -f1 | tr -d ' ')
        hex=$(openssl asn1parse -inform DER -in "$work/s.der" -strparse "$off" |
            grep 'OCTET STRING' | tail -1 | sed 's/.*HEX DUMP\]://' | tr 'A-F' 'a-f')
        echo "$name $alg $hex"
    done
done
