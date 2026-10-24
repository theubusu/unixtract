# Newer Onkyo firmware packages

The Onkyo extractor supports both the original format and a newer format with
an AES-256-CBC wrapper and a revised proprietary bytewise cipher. New-format
support requires an external key profile; no newer vendor key material or
firmware is bundled.

## Usage

Add this collection to a copy of `src/keys.ukf`, replacing the placeholders with
hexadecimal values for your package:

```text
collection "ONKYO_NEW_KEYS": {
    "my-profile": {
        x"<32-byte seed as 64 hex digits>",
        x"<8-byte network key as 16 hex digits>",
        x"<16-byte identifier as 32 hex digits>"
    }
}
```

Multiple profiles may be included. The order of the three values matters.
Keep the existing keys in the file if you also want to extract older packages;
`-k` replaces the built-in key file rather than merging with it.

```sh
unixtract -k my-keys.ukf ONKAVR0025_E70000EAEAEOEO_N.of3 output
```

The `.of3` output is a nested encrypted package. Run the extractor on that output
with the same key file to obtain the network components. It automatically
recognizes this unwrapped inner package. Each invocation uses a separate output
directory. Metadata-only `.of1` packages succeed without emitting payloads.
The `.of0` files remain unsupported. Payloads whose encoding is not recognized
are checksum-validated and saved unchanged, with an explicit message; this
includes the outer non-network components in the tested package. Their output
is not claimed to be decrypted.

## Reproduce the tested key profile

Onkyo's [TX-NR676 support page][support] links the official April 2024 archive
used for validation. Its SHA-256 is
`1bebc6381cf147b67fbb05be86201ac8a40513b65e5893e9eeaa590d29fef44e`.
The archive contains both a legacy `.of4` package and the newer `_N.of*`
packages. The legacy package contains the V850 host component that constructs
the updater's key message, so no receiver access is required.

```sh
curl -LO 'https://assets.onkyo-av.com/product-firmware/ONKAVR0025_E70000EAEAEOEO_N_121.zip?v=1712279175'
unzip ONKAVR0025_E70000EAEAEOEO_N_121.zip
cargo run --release -- ONKAVR0025_E70000EAEAEOEO.of4 legacy-of4
python3 tools/derive_onkyo_new_keys.py legacy-of4/1_EO107.bin \
  --output onkyo-new-keys.ukf
cargo run --release -- -k onkyo-new-keys.ukf \
  ONKAVR0025_E70000EAEAEOEO_N.of2 newer-of2
```

The script checks the extracted EO107 component against SHA-256
`a095f1b5aa83803ff42451260c8e8f11a898bc3aa4431c8861f794e3c24b594b`
before using its verified code offsets. It reconstructs function-parameter
selector `0x1a` from the V850 stores and writes the first 56 body bytes as the
32-byte seed, 8-byte network key, and 16-byte identifier expected by
`ONKYO_NEW_KEYS`. It uses only the Python standard library.

[support]: https://onkyo.com/intl/tx-nr676

## Format and validation

The AES key is SHA-256 of eight selected seed bytes; the IV selects sixteen seed
bytes. See `aes_material` for the indices. The outer AES layer is decrypted
without assuming PKCS#7 padding. Header and table lengths delimit the useful
content; trailing bytes are not interpreted.

After removing the AES layer, the proprietary cipher resets independently for
each header and payload. A nested package must retain its original encrypted
bytes: decrypting the whole nested file as one stream corrupts its entries.
New-format detection checks the identifier and header checksum. Extraction
checks table bounds, component names, and every populated payload checksum.
These rotating word-sum checksums detect corruption; they are not signatures.

The decoder was independently reconstructed from a publicly downloadable
TX-NR676 update package. Its older, extractable network software includes both
cipher implementations, the AES stream reader, and key derivation. The host
controller's function-parameter message supplies the key material. The new
proprietary cipher expands an eight-byte key into a sixteen-byte table and uses
byte rotations, two cycling table indices, and a byte counter.

Verified locally against the April 2024 TX-NR676 package
`ONKAVR0025_E70000EAEAEOEO_N_121_2024-04-05-011615_vqok`:

- Outer `.of1` through `.of4` header checksums and all populated payload checksums.
- Nested `AM335XEO_010203040506`, version `121`, and its four components.
- Extracted ARM Linux uImage header and payload CRCs.
- Extracted UBI filesystem and independently decoded component hashes.

This is evidence for that package, not a compatibility claim for all Onkyo
models or future formats. The tests use synthetic keys and generated packages,
including nested packages, corruption, metadata-only files, and invalid ranges.
No device access, firmware installation, or repacking is performed.
