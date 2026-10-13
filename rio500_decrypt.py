#!/usr/bin/env python3
"""Diamond Rio 500 firmware extractor and offline decryptor.

Read-only tool. Supports RIO500FW raw firmware, embedded update EXEs, CAB-wrapped
InstallShield updaters, and ZIP archives. Uses the recovered Rio 500-specific
16-bit Blowfish variant and static constants from the Rio 500 recovery flasher.
Never executes a Windows updater, flashes a device, or edits input files.

Python 3.9+ standard library required. CAB handling uses system expand.exe on
Windows or libarchive/cabextract/7z/bsdtar when available on Linux/macOS.

Examples:
  python rio500_decrypt.py --selftest
  python rio500_decrypt.py Rio500_v215_FW_Raw.bin
  python rio500_decrypt.py rio500_flash_215.exe
  python rio500_decrypt.py rio500_firmware_215.exe
  python rio500_decrypt.py ./downloads -o decrypted --recursive
"""
from __future__ import annotations
import argparse
import ctypes
import io
import json
import hashlib
import struct
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

MAGIC = b"RIO500FW"
IMAGE_SIZE = 0x14000
BODY_OFF = 0x4000
HEADER_BLOB = slice(0x10, 0x90)
MAX_INPUT = 300 * 1024 * 1024  # also used to reject archive bombs
MAX_MEMBER = 64 * 1024 * 1024
MAX_DEPTH = 7

# Recovered from Rio 500 recovery flasher RCDATA/1002, NOT Rio 600 values.
# Reference SHA256 of original recovery resource:
# 89717cb36fe63087b2d28d10c0896be3fde2f623afca7bba2a2058e493ee34c5
STATIC_64=bytes.fromhex('327698124599fa0307045431001187ffda2e6af02b14449fee78790173dde1aa' 'bb110a09f3811a01716579dd22ecb3d543117cc10861ccca2198a9417344f1aa')
PI_82_RAW=bytes.fromhex('886ad3082e8a44732238d03198fa896ce6217713cf666c0cb729dd50b5d517' '09d9d51bfba60bacb5db72b7dfedaf967e4590997f4799f76ce2f216fcd82' '0694ea3fe7e3d8f7458b658cdee4a1da4b55939d5136023b0f0851879ef38b0d' 'c0e188b0e3e8ac177274bda2f605cf32594ab629840146a39b610345ccee8af' '8693e911142abc5dc5f631163e1e9333ba5ccf815377869848afb91be89321c' 'c0991a960ac3280')
class Blowfish16:
 def __init__(self,key):
  seed=struct.unpack('<82H',PI_82_RAW)
  self.p=list(seed[:18]);self.s=list(seed[18:]);
  for i in range(18):
   word=0
   for j in range(4): word|=(key[(i*4+j)%7]&15)<<(12-j*4)
   self.p[i]^=word
  l=r=0
  for i in range(0,18,2):
   l,r=self.encrypt(l,r);self.p[i:i+2]=[l,r]
  for i in range(0,64,2):
   l,r=self.encrypt(l,r);self.s[i:i+2]=[l,r]
 def f(self,x):
  s=self.s;return (((s[(x>>12)&15]+s[16+((x>>8)&15)])^s[32+((x>>4)&15)])+s[48+(x&15)])&65535
 def encrypt(self,l,r):
  l^=self.p[0];r^=self.f(l)^self.p[1]
  for i in range(2,16,2):l^=self.f(r)^self.p[i];r^=self.f(l)^self.p[i+1]
  l^=self.f(r)^self.p[16];r^=self.p[17];return r,l
 def decrypt(self,l,r):
  l^=self.p[17];r^=self.f(l)^self.p[16]
  for i in range(15,1,-2):l^=self.f(r)^self.p[i];r^=self.f(l)^self.p[i-1]
  l^=self.f(r)^self.p[1];r^=self.p[0];return r,l
 def transform(self,body,enc=False):
  b=bytearray(len(body))
  for i in range(0,len(body),4):
   l,r=struct.unpack_from('<HH',body,i);a,c=(self.encrypt if enc else self.decrypt)(l,r);struct.pack_into('<HH',b,i,a,c)
  return bytes(b)

# Independent plaintext hashes from earlier Rio 500 recovery study. Only exact
# matches are marked reference-verified; changed stock builds may differ.
KNOWN_PLAINTEXT = {
    0x211: "db39b4d04bfc25b84e46c9441300a5deea1c4ed2dbb8b8c9f1287b93bedb0ab9",
    0x212: "e6efb9537f03cfbe590e5aeccfed7c36deed2e168cd5394dee81e967ebf6165d",
    0x214: "0f72ae8ee6ba6fccbd3c8d162c04589a220f35a0df8c778ab56b6e4061a5e3c5",
    0x215: "46d8c0aafe900a0e67264daf4bde2c86f3073101cb804fe1085cef1d5f708c21",
    0x216: "e975c6ffe891c5d30dab2ca4b950d2f17cc2b1f9c6b1bf2b0eb982357ea3bc26",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_container(image: bytes) -> tuple[int, int]:
    if len(image) != IMAGE_SIZE or image[:8] != MAGIC:
        raise ValueError("expected an 0x14000-byte RIO500FW image")
    version, signature_len, blob_len, encrypted_len = struct.unpack_from("<HHHH", image, 8)
    if not 0x200 <= version < 0x300:
        raise ValueError(f"unexpected firmware version 0x{version:X}")
    if signature_len != 40 or blob_len != 128:
        raise ValueError("invalid signature/header length fields")
    if not encrypted_len or encrypted_len % 4 or BODY_OFF + encrypted_len > IMAGE_SIZE:
        raise ValueError(f"invalid encrypted-body size {encrypted_len}")
    if any(image[BODY_OFF + encrypted_len:]):
        raise ValueError("nonzero bytes after encrypted payload")
    return version, encrypted_len


def decrypt_image(image: bytes) -> tuple[dict, bytes, bytes]:
    version, ct_len = validate_container(image)
    key = hashlib.sha1(STATIC_64 + image[HEADER_BLOB]).digest()[:7]
    cipher = Blowfish16(key)
    cipher_body = image[BODY_OFF:BODY_OFF + ct_len]
    plain = cipher.transform(cipher_body)
    if cipher.transform(plain, True) != cipher_body:
        raise ValueError("cipher re-encryption check failed")
    plain_hash = digest(plain)
    reference = KNOWN_PLAINTEXT.get(version)
    if reference is None:
        reference_status = "unknown-version-no-reference"
    elif reference == plain_hash:
        reference_status = "verified-reference-match"
    else:
        reference_status = "DIFFERENT-from-reference"
    analysis = bytearray(image)
    analysis[BODY_OFF:BODY_OFF + ct_len] = plain
    strings = [match.decode("latin-1") for match in re.findall(rb"[\x20-\x7e]{8,}", plain)[:40]]
    result = {
        "firmware_version": f"{version >> 8}.{version & 255:02x}",
        "firmware_version_word": f"0x{version:04X}",
        "encrypted_bytes": ct_len,
        "per-image_derived_key_hex": key.hex(),
        "cipher": "Rio 500 modified Blowfish16, 32-bit block, 7-byte SHA1-derived key",
        "original_container_sha256": digest(image),
        "plaintext_body_sha256": plain_hash,
        "reference_status": reference_status,
        "reencryption_roundtrip": True,
        "first_plaintext_bytes_hex": plain[:32].hex(),
        "first_ascii_strings": strings,
    }
    return result, plain, bytes(analysis)


def scan_images(data: bytes, provenance: str):
    """Find raw or PE-resource images using the actual Rio 500 header layout."""
    cursor = 0
    while True:
        cursor = data.find(MAGIC, cursor)
        if cursor < 0:
            break
        if cursor + IMAGE_SIZE <= len(data):
            chunk = data[cursor:cursor + IMAGE_SIZE]
            try:
                validate_container(chunk)
                yield f"{provenance} @0x{cursor:X}", chunk
            except ValueError:
                pass
        cursor += len(MAGIC)


def scan_embedded_cabs(data: bytes):
    """Extract CABs using genuine MSCF header fields, not just string hits."""
    pos = 0
    while True:
        pos = data.find(b"MSCF", pos)
        if pos == -1:
            return
        if pos + 36 <= len(data):
            size = struct.unpack_from("<I", data, pos + 8)[0]
            folders = struct.unpack_from("<H", data, pos + 26)[0]
            files = struct.unpack_from("<H", data, pos + 28)[0]
            flags = struct.unpack_from("<H", data, pos + 30)[0]
            if (36 <= size <= MAX_MEMBER and pos + size <= len(data)
                and data[pos + 25] == 1 and 0 < folders < 64
                and 0 < files < 4096 and not (flags & ~7)):
                yield pos, data[pos:pos + size]
        pos += 4


def cab_libarchive(cab: bytes) -> list[tuple[str, bytes]]:
    """Read MS CAB (including LZX) through libarchive via ctypes, no pip deps."""
    lib = None
    for name in ("libarchive.so.13", "libarchive.so", "libarchive.dylib", "archive.dll"):
        try:
            lib = ctypes.CDLL(name)
            break
        except OSError:
            pass
    if lib is None:
        raise RuntimeError("libarchive unavailable")
    P = ctypes.c_void_p
    lib.archive_read_new.restype = P
    for sym in ("archive_read_support_format_all", "archive_read_support_filter_all", "archive_read_free"):
        getattr(lib, sym).argtypes = [P]
    lib.archive_read_open_filename.argtypes = [P, ctypes.c_char_p, ctypes.c_size_t]
    lib.archive_read_open_filename.restype = ctypes.c_int
    lib.archive_read_next_header.argtypes = [P, ctypes.POINTER(P)]
    lib.archive_read_next_header.restype = ctypes.c_int
    lib.archive_read_data.argtypes = [P, P, ctypes.c_size_t]
    lib.archive_read_data.restype = ctypes.c_ssize_t
    lib.archive_entry_pathname.argtypes = [P]
    lib.archive_entry_pathname.restype = ctypes.c_char_p
    lib.archive_entry_size.argtypes = [P]
    lib.archive_entry_size.restype = ctypes.c_int64
    lib.archive_error_string.argtypes = [P]
    lib.archive_error_string.restype = ctypes.c_char_p
    with tempfile.TemporaryDirectory(prefix="rio500cab_") as folder:
        path = Path(folder) / "firmware.cab"
        path.write_bytes(cab)
        h = lib.archive_read_new()
        if not h:
            raise RuntimeError("libarchive allocation failed")
        contents = []
        try:
            lib.archive_read_support_format_all(h)
            lib.archive_read_support_filter_all(h)
            if lib.archive_read_open_filename(h, os.fsencode(path), 10240) < 0:
                raise ValueError("unable to open CAB")
            ent = P()
            while True:
                status = lib.archive_read_next_header(h, ctypes.byref(ent))
                if status == 1:  # ARCHIVE_EOF
                    break
                if status < 0:
                    msg = lib.archive_error_string(h)
                    raise ValueError("CAB header error: " + (msg or b"unknown").decode(errors="replace"))
                name = (lib.archive_entry_pathname(ent) or b"").decode(errors="replace")
                size = lib.archive_entry_size(ent)
                if name.endswith("/") or not name:
                    continue
                if size > MAX_MEMBER:
                    raise ValueError("oversize CAB member rejected")
                chunk = ctypes.create_string_buffer(65536)
                buf = bytearray()
                while True:
                    n = lib.archive_read_data(h, chunk, len(chunk))
                    if n == 0:
                        break
                    if n < 0:
                        raise ValueError("CAB data extraction failed")
                    buf.extend(chunk.raw[:n])
                    if len(buf) > MAX_MEMBER:
                        raise ValueError("oversize extracted CAB member rejected")
                contents.append((name, bytes(buf)))
        finally:
            lib.archive_read_free(h)
        return contents


def cab_external(cab: bytes) -> list[tuple[str, bytes]]:
    with tempfile.TemporaryDirectory(prefix="rio500cab_") as tmp:
        folder = Path(tmp)
        input_path = folder / "input.cab"
        target = folder / "out"
        target.mkdir()
        input_path.write_bytes(cab)
        for executable in ("expand.exe", "cabextract", "7z", "7za", "bsdtar"):
            cmd_path = shutil.which(executable)
            if not cmd_path:
                continue
            if executable == "expand.exe":
                command = [cmd_path, "-F:*", str(input_path), str(target)]
            elif executable == "cabextract":
                command = [cmd_path, "-q", "-d", str(target), str(input_path)]
            elif executable in ("7z", "7za"):
                command = [cmd_path, "x", "-y", f"-o{target}", str(input_path)]
            else:
                command = [cmd_path, "-xf", str(input_path), "-C", str(target)]
            try:
                result = subprocess.run(command, timeout=120, capture_output=True, check=False)
            except (OSError, subprocess.TimeoutExpired):
                continue
            if result.returncode:
                continue
            entries = []
            for file in target.rglob("*"):
                if file.is_file() and file.stat().st_size <= MAX_MEMBER:
                    entries.append((str(file.relative_to(target)), file.read_bytes()))
            if entries:
                return entries
    raise RuntimeError("no usable CAB decoder (Windows: expand.exe; Linux: install libarchive/cabextract/7z)")


def cab_members(cab: bytes) -> list[tuple[str, bytes]]:
    try:
        return cab_libarchive(cab)
    except (ValueError, OSError, RuntimeError) as exc:
        try:
            return cab_external(cab)
        except RuntimeError as exc2:
            raise RuntimeError(f"{exc2}; libarchive says: {exc}") from exc


def walk(data: bytes, source: str, depth: int, visited: set[str], errors: list[str]):
    if depth > MAX_DEPTH or len(data) > MAX_INPUT:
        return
    filehash = digest(data)
    if filehash in visited:
        return
    visited.add(filehash)
    yield from scan_images(data, source)

    # Windows PE resources can have the whole image plainly embedded, so the
    # previous scan handles them. InstallShield EXEs may have a nested LZX CAB.
    if zipfile.is_zipfile(io.BytesIO(data)):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist():
                    if info.is_dir() or info.file_size > MAX_MEMBER:
                        continue
                    try:
                        child = archive.read(info)
                    except (ValueError, OSError, RuntimeError, zipfile.BadZipFile):
                        continue
                    yield from walk(child, source + " :: " + info.filename,
                                    depth + 1, visited, errors)
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            errors.append(f"ZIP decode {source}: {exc}")

    for pos, cab in scan_embedded_cabs(data):
        try:
            for name, child in cab_members(cab):
                yield from walk(child, source + f" [CAB@0x{pos:X}] :: {name}",
                                depth + 1, visited, errors)
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(f"CAB decode {source} at 0x{pos:X}: {exc}")


def save(path: Path, content: bytes, overwrite: bool):
    if path.exists():
        if path.read_bytes() == content:
            return
        if not overwrite:
            raise FileExistsError(f"{path} already exists with different contents (use --overwrite)")
    path.write_bytes(content)


def selftest():
    assert len(STATIC_64) == 64
    assert len(PI_82_RAW) == 164
    pi = struct.unpack("<82H", PI_82_RAW)
    assert pi[:3] == (0x6A88, 0x08D3, 0x8A2E) and pi[-1] == 0x8032
    for key in (bytes(7), bytes(range(7)), b"abcdefg"):
        bf = Blowfish16(key)
        for block in (bytes(4), bytes.fromhex("12345678"), b"\xff" * 4):
            assert bf.transform(bf.transform(block, True)) == block
    print("PASS: Rio 500 constants, round-trip block cipher")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("inputs", nargs="*", type=Path, help="raw firmware .bin, EXE, ZIP, or directories")
    p.add_argument("-o", "--outdir", type=Path, default=Path("rio500_decrypted"))
    p.add_argument("--recursive", action="store_true", help="recurse into supplied directories")
    p.add_argument("--body-only", action="store_true", help="do not produce analysis-only full containers")
    p.add_argument("--overwrite", action="store_true", help="replace conflicting existing outputs")
    p.add_argument("--selftest", action="store_true", help="run crypto self-tests")
    args = p.parse_args(argv)
    if args.selftest:
        selftest()
        if not args.inputs:
            return 0
    if not args.inputs:
        p.error("provide input file(s), directories, or --selftest")
    files: list[Path] = []
    for entry in args.inputs:
        if entry.is_file():
            files.append(entry)
        elif entry.is_dir():
            files.extend(f for f in (entry.rglob("*") if args.recursive else entry.glob("*"))
                         if f.is_file() and f.stat().st_size <= MAX_INPUT)
        else:
            print("Cannot find:", entry, file=sys.stderr)
    if not files:
        return 2
    args.outdir.mkdir(parents=True, exist_ok=True)
    processed: set[str] = set()
    reports: list[dict] = []
    failures: list[str] = []
    for path in files:
        print("Scanning", path)
        try:
            if path.stat().st_size > MAX_INPUT:
                raise ValueError("input exceeds safety limit (300 MiB)")
            data = path.read_bytes()
            decode_errors: list[str] = []
            found = False
            for source, image in walk(data, str(path), 0, set(), decode_errors):
                found = True
                fingerprint = digest(image)
                if fingerprint in processed:
                    print("  Duplicate firmware image; skipping")
                    continue
                processed.add(fingerprint)
                report, plain, analysis = decrypt_image(image)
                suffix = f"{report['firmware_version'].replace('.', '_')}_{fingerprint[:10]}"
                body_path = args.outdir / f"rio500_{suffix}_decrypted_body.bin"
                save(body_path, plain, args.overwrite)
                analysis_path = None
                if not args.body_only:
                    analysis_path = args.outdir / f"rio500_{suffix}_analysis_only.bin"
                    save(analysis_path, analysis, args.overwrite)
                report.update(source=source, body_file=str(body_path),
                              analysis_only_container_file=str(analysis_path) if analysis_path else None)
                reports.append(report)
                print("  Rio", report["firmware_version"], "|", report["reference_status"],
                      "| decrypted", len(plain), "bytes")
                print("   ", body_path)
            if not found:
                print("  No recognized Rio 500 firmware container found")
            failures.extend(decode_errors)
        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
            failures.append(f"{path}: {exc}")
    report_path = args.outdir / "rio500_report.json"
    report_path.write_text(json.dumps({"images": reports, "warnings": failures}, indent=2) + "\n", encoding="utf-8")
    print(f"Finished: {len(reports)} firmware images. JSON: {report_path}")
    for failure in failures:
        print("WARNING:", failure, file=sys.stderr)
    if not reports:
        return 1
    return 0 if not failures else 2


if __name__ == "__main__":
    sys.exit(main())
