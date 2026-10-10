#!/usr/bin/env python3
"""Reads what SignTool wrote (see signtool_oracle.ps1) and compares it with rsigncode.

  signtool_oracle.py extract <signtool-dir> <oracle.json>
      <signtool-dir>/raw.json (SignTool and imagehlp, raw) -> oracle.json: for each file
      and algorithm the file digest (from the .p7u of `/dg` and from the signed copy), the
      page hash table, the CheckSum field of the signed copy and the refusals.

  signtool_oracle.py compare <oracle.json> <rsigncode.json> [--committed <oracle.json>]
                             [--signed sha1=<json>] [--signed sha256=<json>] [--strict]
      Markdown table on stdout; with --strict, exit status 1 on a disagreement between
      SignTool/imagehlp and rsigncode. With --committed, also reports (never fails) the
      values that differ from the committed oracle file.

Pure standard library: the DER structures are read by a minimal parser.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

# DER content of the OIDs.
OID_SPC_PE_IMAGE_DATA = bytes.fromhex("2b06010401823702010f")  # 1.3.6.1.4.1.311.2.1.15
OID_PAGE_HASH = {
    bytes.fromhex("2b060104018237020301"): "sha1",  # 1.3.6.1.4.1.311.2.3.1
    bytes.fromhex("2b060104018237020302"): "sha256",  # 1.3.6.1.4.1.311.2.3.2
}
OID_DIGEST = {
    bytes.fromhex("2b0e03021a"): "sha1",
    bytes.fromhex("608648016503040201"): "sha256",
}


# ---------------------------------------------------------------------------- DER


def parse(buf):
    """The TLVs of `buf` as (tag, content). Definite and indefinite lengths."""
    out = []
    off = 0
    while off < len(buf):
        if buf[off] == 0 and (off + 1 >= len(buf) or buf[off + 1] == 0):
            break  # end-of-contents of an indefinite length parent, or padding
        tag = buf[off]
        off += 1
        if tag & 0x1F == 0x1F:
            while buf[off] & 0x80:
                off += 1
            off += 1
        first = buf[off]
        off += 1
        if first == 0x80:  # indefinite: the content ends at 00 00 after its children
            end = off
            while buf[end : end + 2] != b"\0\0":
                _, c = parse_one(buf, end)
                end = c
            out.append((tag, buf[off:end]))
            off = end + 2
            continue
        if first & 0x80:
            n = first & 0x7F
            length = int.from_bytes(buf[off : off + n], "big")
            off += n
        else:
            length = first
        if off + length > len(buf):
            raise ValueError("TLV overruns the buffer")
        out.append((tag, buf[off : off + length]))
        off += length
    return out


def parse_one(buf, off):
    """(tlv, end offset) of the TLV starting at `off` (used for indefinite lengths)."""
    start = off
    off += 1
    first = buf[off]
    off += 1
    if first == 0x80:
        while buf[off : off + 2] != b"\0\0":
            _, off = parse_one(buf, off)
        return None, off + 2
    if first & 0x80:
        n = first & 0x7F
        length = int.from_bytes(buf[off : off + n], "big")
        off += n
    else:
        length = first
    if off + length > len(buf):
        raise ValueError("TLV overruns the buffer")
    return start, off + length


def walk(buf):
    """Every node (tag, content) of the DER tree, also inside OCTET STRINGs that hold DER."""
    try:
        nodes = parse(buf)
    except (ValueError, IndexError):
        return
    for tag, content in nodes:
        yield tag, content
        if tag & 0x20 or tag == 0x04:
            yield from walk(content)


def find_spc_indirect_data(blob):
    """(digest algorithm, digest, SpcPeImageData content) of the first
    SpcIndirectDataContent found in `blob`."""
    for tag, content in walk(blob):
        if tag != 0x30:
            continue
        try:
            kids = parse(content)
            if len(kids) < 2 or kids[0][0] != 0x30 or kids[1][0] != 0x30:
                continue
            data = parse(kids[0][1])
            if data[0] != (0x06, OID_SPC_PE_IMAGE_DATA):
                continue
            algorithm, digest = parse(kids[1][1])
            oid = parse(algorithm[1])[0][1]
            return OID_DIGEST.get(oid, oid.hex()), digest[1].hex(), data[1][1]
        except (ValueError, IndexError):
            continue
    return None


def find_page_hashes(pe_image_data):
    """{algorithm: table (hex)} of the page hash attributes of a SpcPeImageData."""
    found = {}
    for tag, content in walk(pe_image_data):
        if tag != 0x04 or not content or content[0] != 0x31:
            continue
        try:
            # content is a SET of SpcAttributeTypeAndOptionalValue
            for stag, attr in parse(parse(content)[0][1]):
                if stag != 0x30:
                    continue
                oid, value = parse(attr)[:2]
                if oid[1] in OID_PAGE_HASH:
                    found[OID_PAGE_HASH[oid[1]]] = parse(value[1])[0][1].hex()
        except (ValueError, IndexError):
            continue
    return found


# ---------------------------------------------------------------------------- PE


def pe_fields(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    cert = opt + (96 if magic == 0x10B else 112) + 32
    return opt + 64, cert


def certificate_blob(data):
    """PKCS #7 of the first certificate of a signed PE file, and the CheckSum field."""
    checksum_at, cert = pe_fields(data)
    checksum = struct.unpack_from("<I", data, checksum_at)[0]
    offset, size = struct.unpack_from("<II", data, cert)
    if not size:
        return None, checksum
    return data[offset + 8 : offset + size], checksum


# ---------------------------------------------------------------------------- extract


def extract(directory, out_path):
    directory = Path(directory)
    raw = json.loads((directory / "raw.json").read_text(encoding="utf-8-sig"))
    files = {}
    for name, f in raw["files"].items():
        entry = {
            "size": f["size"],
            "map_file_and_checksum": f["map_file_and_checksum"],
            "checksum_mapped_file": f["checksum_mapped_file"],
        }
        for alg in ("sha1", "sha256"):
            r = f[alg]
            dg = {"exit": r["dg"]["exit"], "output": r["dg"]["output"], "digest": None}
            p7u = directory / r["p7u"]
            if r["dg"]["exit"] == 0 and p7u.exists():
                found = find_spc_indirect_data(p7u.read_bytes())
                if found:
                    dg["digest_algorithm"], dg["digest"] = found[0], found[1]
            sign = {
                "exit": r["sign"]["exit"],
                "output": r["sign"]["output"],
                "digest": None,
                "page_hashes": None,
            }
            signed = directory / r["signed"]
            if r["sign"]["exit"] == 0 and signed.exists():
                data = signed.read_bytes()
                blob, sign["checksum_field"] = certificate_blob(data)
                sign["signed_size"] = len(data)
                found = blob and find_spc_indirect_data(blob)
                if found:
                    sign["digest_algorithm"], sign["digest"] = found[0], found[1]
                    tables = find_page_hashes(found[2])
                    sign["page_hashes"] = tables.get(alg)
                    sign["page_hash_algorithms"] = sorted(tables)
            entry[alg] = {"dg": dg, "sign": sign}
        fixture = directory.parent / "fixtures" / f["file"]
        if fixture.exists():
            entry["sha256_of_file"] = hashlib.sha256(fixture.read_bytes()).hexdigest()
        files[name] = entry
    result = {"meta": raw["meta"], "files": files}
    Path(out_path).write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    print(f"{len(files)} files written to {out_path}")


# ---------------------------------------------------------------------------- compare


def offsets_ascending(table_hex, alg):
    entry = 4 + (20 if alg == "sha1" else 32)
    table = bytes.fromhex(table_hex)
    offsets = [
        struct.unpack_from("<I", table, i)[0] for i in range(0, len(table) - entry, entry)
    ]
    return offsets == sorted(offsets)


def short(value):
    return "-" if value is None else value[:12] + "..."


def one_line(text):
    return " ".join((text or "").split()).replace("|", "/")


def compare(oracle_path, rsigncode_path, committed_path, strict, signed_paths):
    oracle = json.loads(Path(oracle_path).read_text())
    signed = {a: json.loads(Path(p).read_text()) for a, p in signed_paths.items()}
    ours = json.loads(Path(rsigncode_path).read_text())
    committed = None
    if committed_path and Path(committed_path).exists():
        committed = json.loads(Path(committed_path).read_text())
    failures = []
    drift = []
    meta = oracle["meta"]
    lines = [
        "## SignTool oracle vs rsigncode",
        "",
        f"SignTool {meta['signtool_version']}, imagehlp {meta['imagehlp_version']}, "
        f"{meta['os']}, runner image {meta.get('image_os')} {meta.get('image_version')}",
        "",
        "Legend: `ok` same value; `MISMATCH`; `both refuse`; `ST refuses`: SignTool refuses and "
        "rsigncode computes a value; `RS refuses`: SignTool accepts and rsigncode refuses.",
        "",
        "| fixture | size | SHA-1 digest | SHA-256 digest | SHA-1 pages | SHA-256 pages | "
        "pages by offset | checksum (MapFileAndCheckSum) | checksum (CheckSumMappedFile) | "
        "rsigncode on the file signed by SignTool (CheckSum field, digest) |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    refusals = []
    for name, st in oracle["files"].items():
        rs = ours.get(name)
        if rs is None:
            failures.append(f"{name}: no rsigncode result")
            continue
        cells = [name, str(st["size"])]
        quirk = []

        def verdict(label, expected, ours_value, ours_error, st_refusal):
            if expected is None:
                if ours_value is None:
                    refusals.append((name, label, st_refusal, ours_error))
                    return "both refuse"
                refusals.append((name, label, st_refusal, None))
                return "ST refuses"
            if ours_value is None:
                failures.append(f"{name} {label}: SignTool accepts, rsigncode refuses ({ours_error})")
                return "RS refuses"
            if expected != ours_value:
                failures.append(f"{name} {label}: SignTool {expected} != rsigncode {ours_value}")
                return "MISMATCH"
            return "ok"

        for alg in ("sha1", "sha256"):
            dg = st[alg]["dg"]
            cells.append(
                verdict(f"{alg} digest", dg["digest"], rs[alg]["digest"], rs[alg]["digest_error"], dg["output"])
            )
            sign = st[alg]["sign"]
            if sign["digest"] and dg["digest"] and sign["digest"] != dg["digest"]:
                failures.append(f"{name} {alg}: digest of /dg and of the signed copy differ")
        for alg in ("sha1", "sha256"):
            sign = st[alg]["sign"]
            cells.append(
                verdict(
                    f"{alg} page hashes",
                    sign["page_hashes"],
                    rs[alg]["page_hashes"],
                    rs[alg]["page_hashes_error"],
                    sign["output"],
                )
            )
            if sign["page_hashes"]:
                quirk.append(str(offsets_ascending(sign["page_hashes"], alg)))
        cells.append("/".join(quirk) or "-")
        mf = st["map_file_and_checksum"]
        expected = mf["checksum"] if mf["ret"] == 0 else None
        cells.append(verdict("checksum (MapFileAndCheckSum)", expected, rs["checksum"], rs["checksum_error"], "imagehlp"))
        cm = st["checksum_mapped_file"]
        expected = cm["checksum"] if cm["found_headers"] else None
        cells.append(verdict("checksum (CheckSumMappedFile)", expected, rs["checksum"], rs["checksum_error"], "imagehlp"))
        # The value SignTool writes in the signed copy: the checksum of the signed file,
        # which is not the checksum of the unsigned one (not compared).
        # rsigncode on the signed copies (`--signed alg=json`): same checksum and same digest.
        signed_ok = []
        for alg, table in signed.items():
            sign = st[alg]["sign"]
            copy = table.get(name)
            if sign["exit"] != 0 or copy is None:
                continue
            for label, expected, got in (
                ("checksum", sign["checksum_field"], copy["checksum"]),
                ("digest", sign["digest"], copy[alg]["digest"]),
            ):
                if expected != got:
                    failures.append(f"{name} {alg} signed copy {label}: SignTool {expected} != rsigncode {got}")
                signed_ok.append(f"{alg} {label} {'ok' if expected == got else 'MISMATCH'}")
        cells.append(", ".join(signed_ok) or "-")
        lines.append("| " + " | ".join(cells) + " |")

        if committed:
            old = committed["files"].get(name)
            if old is None:
                drift.append(f"{name}: not in the committed oracle")
            else:
                for key in ("map_file_and_checksum", "checksum_mapped_file", "sha256_of_file"):
                    if old.get(key) != st.get(key):
                        drift.append(f"{name} {key}")
                for alg in ("sha1", "sha256"):
                    for part, fields in (("dg", ("digest",)), ("sign", ("digest", "page_hashes", "checksum_field"))):
                        for field in fields:
                            if old[alg][part].get(field) != st[alg][part].get(field):
                                drift.append(f"{name} {alg} {part} {field}")
                    for part in ("dg", "sign"):
                        if (old[alg][part]["exit"] == 0) != (st[alg][part]["exit"] == 0):
                            drift.append(f"{name} {alg} {part} accepted/refused")

    lines += ["", "### SignTool refusals", ""]
    seen = [r for r in refusals if r[2] not in (None, "imagehlp")]
    if seen:
        lines += ["| fixture | value | SignTool message | rsigncode |", "|---|---|---|---|"]
        for name, label, message, error in seen:
            lines.append(f"| {name} | {label} | {one_line(message)} | {error or 'computes a value'} |")
    else:
        lines.append("None.")
    imagehlp = [r for r in refusals if r[2] == "imagehlp"]
    if imagehlp:
        lines += ["", "imagehlp finds no PE headers (rsigncode agrees): " + ", ".join(f"{r[0]} ({r[1]})" for r in imagehlp)]
    if committed:
        lines += ["", "### Drift from the committed oracle", ""]
        lines += [f"- {d}" for d in drift] or ["None."]
    lines += ["", "### Disagreements between SignTool/imagehlp and rsigncode", ""]
    lines += [f"- {f}" for f in failures] or ["None."]
    print("\n".join(lines))
    if failures and strict:
        sys.exit(1)


def main():
    args = sys.argv[1:]
    if len(args) == 3 and args[0] == "extract":
        extract(args[1], args[2])
    elif len(args) >= 3 and args[0] == "compare":
        committed = args[args.index("--committed") + 1] if "--committed" in args else None
        signed = dict(
            args[i + 1].split("=", 1) for i, a in enumerate(args) if a == "--signed"
        )
        compare(args[1], args[2], committed, "--strict" in args, signed)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
