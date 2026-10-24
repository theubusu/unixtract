#!/usr/bin/env python3
"""Recover the TX-NR676 newer-package key profile from official firmware.

The April 2024 Onkyo archive contains both the legacy ``.of4`` package and the
newer ``_N.of*`` packages.  Extract the legacy ``.of4`` with unixtract first,
then pass its ``1_EO107.bin`` component to this script.  The V850 controller
code constructs function-parameter message 0x1a one byte at a time; the first
56 bytes of its body are the seed, network key, and identifier consumed by the
network updater.

This intentionally supports only the independently verified EO107 image.  The
SHA-256 check prevents fixed offsets from silently producing a wrong profile on
another firmware version.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


EO107_SHA256 = "a095f1b5aa83803ff42451260c8e8f11a898bc3aa4431c8861f794e3c24b594b"
CODE_START = 0x3BCC
CODE_END = 0x3EDC
MESSAGE_HEADER = bytes.fromhex("e3ffff69001a")
MESSAGE_LENGTH = 110


class DerivationError(ValueError):
    """The input does not contain the verified key-message construction."""


def reconstruct_message(image: bytes) -> bytes:
    code = image[CODE_START:CODE_END]
    if len(code) != CODE_END - CODE_START:
        raise DerivationError("EO107 image is truncated before the key-message code")

    registers: dict[int, int] = {0: 0}
    stores: dict[int, int] = {}
    offset = 0

    while offset < len(code):
        if offset + 2 > len(code):
            raise DerivationError("truncated V850 instruction")
        first, second = code[offset : offset + 2]

        # movea imm16, r0, rN
        if first == 0x20 and second & 0x07 == 0x06:
            if offset + 4 > len(code):
                raise DerivationError("truncated V850 movea instruction")
            register = second >> 3
            registers[register] = int.from_bytes(code[offset + 2 : offset + 4], "little")
            offset += 4
            continue

        # st.b rN, disp16[r29]
        if first == 0x5D and second & 0x07 == 0x07:
            if offset + 4 > len(code):
                raise DerivationError("truncated V850 st.b instruction")
            register = second >> 3
            displacement = int.from_bytes(code[offset + 2 : offset + 4], "little")
            if register not in registers:
                raise DerivationError(f"store uses unset V850 register r{register}")
            if displacement in stores:
                raise DerivationError(f"duplicate message-byte store at {displacement:#x}")
            stores[displacement] = registers[register] & 0xFF
            offset += 4
            continue

        # mov imm5, rN.  The one add instruction in this exact sequence does
        # not contribute to the message and is accepted explicitly below.
        if first < 0x20 and second & 0x07 == 0x02:
            registers[second >> 3] = first & 0x1F
            offset += 2
            continue

        if code[offset : offset + 2] == b"\x41\xe2":  # add 1, r28
            offset += 2
            continue

        address = CODE_START + offset
        raise DerivationError(f"unexpected V850 instruction at {address:#x}")

    expected_offsets = set(range(MESSAGE_LENGTH))
    actual_offsets = set(stores)
    if actual_offsets != expected_offsets:
        missing = sorted(expected_offsets - actual_offsets)
        extra = sorted(actual_offsets - expected_offsets)
        raise DerivationError(f"incomplete key message; missing={missing}, extra={extra}")

    message = bytes(stores[index] for index in range(MESSAGE_LENGTH))
    if not message.startswith(MESSAGE_HEADER):
        raise DerivationError("reconstructed function-parameter header does not match selector 0x1a")
    return message


def render_ukf(message: bytes, profile: str) -> str:
    body = message[len(MESSAGE_HEADER) :]
    seed = body[:32]
    network_key = body[32:40]
    identifier = body[40:56]
    if len(seed) != 32 or len(network_key) != 8 or len(identifier) != 16:
        raise DerivationError("reconstructed key structure has the wrong length")
    return (
        'collection "ONKYO_NEW_KEYS": {\n'
        f'    "{profile}": {{\n'
        f'        x"{seed.hex().upper()}",\n'
        f'        x"{network_key.hex().upper()}",\n'
        f'        x"{identifier.hex().upper()}"\n'
        "    }\n"
        "}\n"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="derive a unixtract UKF profile from the verified Onkyo EO107 image"
    )
    parser.add_argument("eo107", type=Path, help="legacy extraction output 1_EO107.bin")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write the UKF profile here instead of standard output",
    )
    parser.add_argument(
        "--profile",
        default="tx-nr676-121",
        help="profile name in the generated UKF collection",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        image = args.eo107.read_bytes()
        digest = hashlib.sha256(image).hexdigest()
        if digest != EO107_SHA256:
            raise DerivationError(
                f"unexpected EO107 SHA-256 {digest}; expected {EO107_SHA256}"
            )
        profile = render_ukf(reconstruct_message(image), args.profile)
        if args.output:
            args.output.write_text(profile, encoding="ascii")
        else:
            sys.stdout.write(profile)
    except (OSError, DerivationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
