#!/usr/bin/env python3
"""Patch .gnu.version_r vna_hash entries after a string-only replacement.

Our earlier hex-edit rewrote the version-name strings in .dynstr from
LIBVIRT_10.1.0 / 10.2.0 / 11.2.0 to LIBVIRT_1.2.14 / 1.2.15 / 1.2.16
(same byte length), but vna_hash on each Vernaux still reflects the old
name — so glibc's ld.so fails verneed matching with
"version `LIBVIRT_1.2.15' not found" on libraries that do provide it.

This script rewrites each Vernaux.vna_hash that points (via vna_name) at
a patched string, to the elf_hash of the new string value. Only those
entries are touched; everything else is left alone.
"""
import struct
import sys
from elftools.elf.elffile import ELFFile


def elf_hash(s: bytes) -> int:
    h = 0
    for c in s:
        h = (h << 4) + c
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= 0x0FFFFFFF
    return h


RENAMES = {
    b"LIBVIRT_1.2.14": elf_hash(b"LIBVIRT_1.2.14"),
    b"LIBVIRT_1.2.15": elf_hash(b"LIBVIRT_1.2.15"),
    b"LIBVIRT_1.2.16": elf_hash(b"LIBVIRT_1.2.16"),
}


def main(path: str) -> None:
    # First pass: collect offsets of every Vernaux whose name matches a renamed string.
    patches = []  # list of (file_offset_of_vna_hash, new_hash)
    with open(path, "rb") as f:
        elf = ELFFile(f)
        verneed = elf.get_section_by_name(".gnu.version_r")
        if verneed is None:
            sys.exit("No .gnu.version_r section")
        dynstr = elf.get_section_by_name(".dynstr")
        # Walk Verneed -> Vernaux chain manually; pyelftools' iter_versions() varies across versions.
        base_off = verneed["sh_offset"]
        data = verneed.data()
        # Elf64_Verneed:   uint16 vn_version, vn_cnt; uint32 vn_file; uint32 vn_aux, vn_next
        # Elf64_Vernaux:   uint32 vna_hash; uint16 vna_flags, vna_other; uint32 vna_name, vna_next
        cursor = 0
        while True:
            vn_version, vn_cnt, vn_file, vn_aux, vn_next = struct.unpack_from(
                "<HHIII", data, cursor
            )
            aux_cursor = cursor + vn_aux
            for i in range(vn_cnt):
                vna_hash, vna_flags, vna_other, vna_name, vna_next = struct.unpack_from(
                    "<IHHII", data, aux_cursor
                )
                name = dynstr.get_string(vna_name).encode()
                if name in RENAMES:
                    new_hash = RENAMES[name]
                    file_off = base_off + aux_cursor  # offset of vna_hash (first field)
                    patches.append((file_off, new_hash, name))
                if vna_next == 0:
                    break
                aux_cursor += vna_next
            if vn_next == 0:
                break
            cursor += vn_next

    with open(path, "r+b") as f:
        for off, new_hash, name in patches:
            f.seek(off)
            old = struct.unpack("<I", f.read(4))[0]
            if old == new_hash:
                print(f"  skip: {name.decode()} @0x{off:x} already 0x{new_hash:08x}")
                continue
            f.seek(off)
            f.write(struct.pack("<I", new_hash))
            print(f"  patched {name.decode()} @0x{off:x}: 0x{old:08x} -> 0x{new_hash:08x}")

    print(f"done; {len(patches)} entries inspected")


if __name__ == "__main__":
    main(sys.argv[1])
