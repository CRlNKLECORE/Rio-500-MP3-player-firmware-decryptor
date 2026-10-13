# Rio 500 Firmware Decryptor

I went looking through old Diamond Rio firmware because I wanted to figure out what these things were doing with their audio hardware. Somewhere along the way, that turned into reverse engineering the Rio 500 firmware encryption. That's usually how these projects go.

This is a Python tool for pulling **decrypted Rio 500 firmware** out of raw `.bin` files and the original Windows firmware update packages. You can hand it an updater `.exe` instead of manually digging through resources or extracting a bunch of nested archives yourself.

It doesn't need a Rio 500, and it doesn't run the updater. Everything happens offline.

## What it does

- Finds `RIO500FW` images in raw firmware files, Windows updater EXEs, and ZIP archives.
- Digs through embedded Microsoft CAB archives, including the ones used by some InstallShield updaters.
- Derives the per-image key and decrypts the firmware payload using the **Rio 500-specific modified Blowfish16 cipher**.
- Checks that the decrypted payload encrypts back to the original ciphertext.
- Compares the decrypted SHA-256 against known reference hashes where available.
- Dumps the decrypted firmware body, an analysis-only copy of the original container, and a JSON report with hashes, keys, and some useful strings.
- Can chew through a directory of firmware packages in one go.

**This is for the Rio 500.** The Rio 600 uses different crypto parameters. You can't just swap in Rio 600 constants and expect this to work.

## Requirements

- Python **3.9+**
- No `pip install` required. The script itself only uses the Python standard library.
- On Windows, `expand.exe` is used when CAB extraction is needed.
- On Linux/macOS, CAB extraction can use `libarchive`, `cabextract`, `7z`/`7za`, or `bsdtar` if available. Ordinary raw firmware and directly embedded images don't need any of these.

## Usage

Put `rio500_decrypt.py` wherever you want and run it against a firmware image or updater.

### Raw firmware

```bash
python rio500_decrypt.py Rio500_v215_FW_Raw.bin -o decrypted
```

### Windows firmware updater

```bash
python rio500_decrypt.py rio500_firmware_215.exe -o decrypted
```

The `.exe` is treated as data. **It is never executed.** The script searches for the firmware image directly and also handles supported archive wrappers.

### A whole folder of firmware

```bash
python rio500_decrypt.py ./firmware_downloads --recursive -o decrypted
```

### Self-test

```bash
python rio500_decrypt.py --selftest
```

That tests the cipher constants and block encryption/decryption round trips. It isn't a substitute for checking the output against an actual firmware reference.

### Options

| Option | What it does |
| --- | --- |
| `-o`, `--outdir` | Directory to write the decrypted files and report to. Defaults to `rio500_decrypted`. |
| `--recursive` | Recurse through directories supplied as inputs. |
| `--body-only` | Don't write the analysis-only full container. |
| `--overwrite` | Replace output files if the names already exist with different contents. |
| `--selftest` | Run the built-in cipher tests. |

You can also pass multiple input files in the same command.

## Output

For each unique firmware image, you'll get something like:

```text
decrypted/
├── rio500_2_15_34a5889fc4_decrypted_body.bin
├── rio500_2_15_34a5889fc4_analysis_only.bin
└── rio500_report.json
```

- **`*_decrypted_body.bin`** is the actual decrypted payload. This is what you probably want to load into your disassembler or start taking apart.
- **`*_analysis_only.bin`** is an 0x14000-byte copy of the original `RIO500FW` container with its encrypted body replaced by plaintext. It's handy for comparing offsets against the original image, but **it is not a valid firmware update image and should not be flashed**.
- **`rio500_report.json`** records where the firmware was found, the version, the derived key, sizes, hashes, reference status, the encryption round-trip result, and printable strings recovered from the payload.

Output filenames include part of the original image's SHA-256 so multiple builds of the same firmware version don't stomp on each other.

## How the decryption works

The raw Rio 500 firmware image is an **0x14000-byte** container beginning with `RIO500FW`. The encrypted payload starts at file offset **`0x4000`**. Its actual length comes from the container header rather than an assumption that the whole rest of the file is encrypted.

The interesting part was in the Rio 500 recovery flasher. Its recovery resource contains the constants and cipher logic needed to reconstruct the encryption scheme. The implementation here uses:

1. A 64-byte constant recovered from the Rio 500 recovery flasher.
2. The 128-byte firmware header region at `0x10:0x90`.
3. SHA-1 over those bytes, taking the first seven bytes as the per-image key.
4. The Rio 500's modified 16-bit Blowfish implementation, operating on **32-bit blocks**.

In Python terms, the key derivation is:

```python
key = hashlib.sha1(recovery_constant + image[0x10:0x90]).digest()[:7]
```

The Blowfish implementation uses its own 16-bit P/S tables and round function. Standard Blowfish libraries won't decrypt this firmware, and the Rio 600's tables aren't interchangeable with these ones.

The script also checks the firmware's header layout before attempting decryption. After decrypting, it encrypts the result again and compares it with the original encrypted body. That confirms the cipher transformation is internally consistent, although a **known plaintext hash match** is the stronger confirmation that the actual firmware was recovered correctly.

## Verification

I verified the decryptor against an original **Rio 500 v2.15** firmware image. The resulting plaintext contains the expected firmware strings, including `NO TRACKS`, `Low Battery`, `Equalizer`, `BackLight`, `Settings`, and `Version 2.15`.

```text
Firmware:          Rio 500 v2.15
Encrypted bytes:   65324
Reference status:  verified-reference-match
Plaintext SHA-256: 46d8c0aafe900a0e67264daf4bde2c86f3073101cb804fe1085cef1d5f708c21
```

The script also has reference plaintext hashes for versions **2.11, 2.12, 2.14, 2.15, and 2.16**. It's not hardcoded to only accept those versions, though. Other Rio 500 images with the same recognized container format can be attempted; they just won't get a reference match unless their decrypted hash matches one of the recorded values.

A `DIFFERENT-from-reference` result means exactly that: the output differs from the known hash for that version. It doesn't automatically mean the decryptor failed, since different builds can exist.

The raw v2.15 path has been checked against a real firmware image. EXE, ZIP, and CAB handling was also exercised with constructed test packages. I haven't tested every historical updater somebody might have sitting on an old hard drive, so if you find one that doesn't extract, that's worth investigating.

## A few things this doesn't do

- It does **not** flash a Rio, modify the input files, or communicate with a player.
- It does **not** verify or regenerate the firmware's original signature.
- It does **not** automatically identify, disassemble, or emulate whatever CPU/DSP code is inside the decrypted payload.
- It does **not** decrypt Rio 600 firmware.
- It does **not** promise support for every installer wrapper ever used to distribute these updates.

I'm publishing the decryptor, **not the proprietary Rio firmware images**. You'll need to provide those yourself.

## Why I bothered

The whole point of this is to get the firmware into a state where it can actually be researched. Once the encryption is out of the way, we can start mapping code, hunting for hardware initialization routines, comparing versions, and figuring out which bits talk to the audio hardware instead of staring at ciphertext.

If you've got an odd Rio 500 updater that this doesn't recognize, an unknown firmware revision, or documentation on the old Diamond/Micronas internals, that's exactly the kind of stuff I'm interested in.
