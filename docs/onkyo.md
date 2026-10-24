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
