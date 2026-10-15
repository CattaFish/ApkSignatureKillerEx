#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal AXML (Android Binary XML) modifier.
Parses string pool, finds <application android:name="...">,
appends "r.k.app" to string pool, rewrites the attribute reference.
No third-party dependencies.
"""
import struct

# chunk types
RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103

UTF8_FLAG = 0x100

ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"

class StringPool:
    def __init__(self, buf, off):
        self.buf = buf
        self.off = off
        (self.type, self.header_size, self.chunk_size,
         self.string_count, self.style_count, self.flags,
         self.strings_start, self.styles_start) = struct.unpack_from("<HHIIIIII", buf, off)
        self.utf8 = (self.flags & UTF8_FLAG) != 0
        self.is_utf16 = not self.utf8
        # string offsets are relative to start of this chunk
        self.offsets = list(struct.unpack_from("<" + "I" * self.string_count, buf, off + 28))

    def get_string(self, idx):
        if idx < 0 or idx >= self.string_count:
            return None
        str_off = self.off + self.offsets[idx]
        if self.utf8:
            # UTF-8: u16len (1 or 2 bytes), then null terminated
            p = str_off
            # skip utf16 length (2 bytes if first >= 0x80)
            b0 = self.buf[p]; p += 1
            if b0 & 0x80:
                p += 1
            # utf8 length (1 or 2 bytes)
            b1 = self.buf[p]; p += 1
            if b1 & 0x80:
                p += 1
            # string bytes until \x00
            start = p
            while p < len(self.buf) and self.buf[p] != 0:
                p += 1
            return self.buf[start:p].decode("utf-8", errors="replace")
        else:
            # UTF-16 length (2 bytes), then null terminated (2-byte null)
            (u16len,) = struct.unpack_from("<H", self.buf, str_off)
            start = str_off + 2
            end = start + u16len * 2
            raw = self.buf[start:end]
            return raw.decode("utf-16-le", errors="replace")

    def append_utf8_string(self, s):
        """Append a UTF-8 encoded string to pool, return new index."""
        # Build the encoded entry: utf16 len (we just write 1 byte for len), utf8 len, bytes, \0
        data = s.encode("utf-8")
        # We'll append after last string data. Existing string data region ends somewhere.
        # We track the max end of string data.
        # offsets are relative to chunk start; strings_start is relative to chunk start.
        # We simply append at the end of the chunk's string data (before styles if any).
        # Find end of current string data: scan all strings, compute max offset + encoded length.
        max_end = 0
        for idx in range(self.string_count):
            end = self._string_data_end(idx)
            if end > max_end:
                max_end = end
        # Bytes to insert: utf16_len (for UTF-8, 1 or 2 bytes), utf8_len, data, \0
        # For simplicity, encode lengths with small form (>=0x80 uses multibyte; we handle both).
        def encode_len(n):
            if n < 0x80:
                return bytes([n])
            else:
                return bytes([(n & 0x7F) | 0x80, (n >> 7) & 0xFF])
        u16len = len(data)  # in chars, for UTF-8 this is byte count approx; okay for short
        u8len = len(data)
        entry = encode_len(u16len) + encode_len(u8len) + data + b"\x00"
        new_off = max_end
        # insert into buffer
        insert_at = self.off + new_off
        self.buf = self.buf[:insert_at] + entry + self.buf[insert_at:]
        # update offsets list
        self.offsets.append(new_off)
        # update chunk size and counts
        self.string_count += 1
        self.chunk_size += len(entry)
        struct.pack_into("<I", self.buf, self.off + 8, self.chunk_size)  # chunk_size
        struct.pack_into("<I", self.buf, self.off + 12, self.string_count)  # stringCount
        # append offset to offsets array: after initial 28-byte header + count*4
        offsets_array_off = self.off + 28
        # need to insert 4 bytes to array
        insert_at = offsets_array_off + (self.string_count - 1) * 4
        self.buf = self.buf[:insert_at] + struct.pack("<I", new_off) + self.buf[insert_at:]
        # Since array insertion after header, all existing offsets remain valid (array is before string data).
        return self.string_count - 1

    def _string_data_end(self, idx):
        """Return absolute end offset of the encoded string data for given index."""
        str_off = self.off + self.offsets[idx]
        p = str_off
        if self.utf8:
            b0 = self.buf[p]; p += 1
            if b0 & 0x80:
                p += 1
            b1 = self.buf[p]; p += 1
            if b1 & 0x80:
                p += 1
            while self.buf[p] != 0:
                p += 1
            return p + 1
        else:
            (u16len,) = struct.unpack_from("<H", self.buf, p)
            return str_off + 2 + u16len * 2 + 2

    def rebuild_offsets(self):
        """After length changes, need rewrite offsets? Offsets are relative to chunk start unaffected."""
        pass

def extract_string_pool(buf):
    """Get string pool chunk info."""
    off = 0
    # header
    (file_type, file_header, file_size) = struct.unpack_from("<HHI", buf, 0)
    if file_type != 0x0003:
        raise ValueError("Not a binary XML (type=%#x)" % file_type)
    return StringPool(buf, 8)  # first chunk usually string pool at offset 8

def find_application_start_element(buf, pool):
    """Find start element with name 'application', return (offset, attr_count, attrs_start)."""
    off = 8 + pool.chunk_size  # after string pool
    # Also skip possible resource map / namespace chunks
    while off + 8 <= len(buf):
        (ctype, cheader, csize) = struct.unpack_from("<HHI", buf, off)
        if ctype == RES_XML_START_ELEMENT_TYPE:
            # header: type(2), header_size(2), size(4), line(4), comment(4), ns(4), name(4), attrStart(2), attrSize(2), attrCount(2), idIndex(2), classIndex(2), styleIndex(2)
            if csize < 36:
                return None
            (ns_idx, name_idx) = struct.unpack_from("<II", buf, off + 16)
            attr_start_off = off + 36
            (attr_count,) = struct.unpack_from("<H", buf, off + 32)
            name = pool.get_string(name_idx)
            if name == "application":
                return off, attr_count, attr_start_off
        if csize < 8:
            return None
        off += csize
    return None

def modify_application_name(axml_bytes, new_name="r.k.app"):
    """Return modified AXML bytes with application android:name set to new_name."""
    buf = bytearray(axml_bytes)
    pool = StringPool(buf, 8)

    # find application start element
    found = None
    off = 8 + pool.chunk_size
    while off + 8 <= len(buf):
        (ctype, cheader, csize) = struct.unpack_from("<HHI", buf, off)
        if ctype == RES_XML_START_ELEMENT_TYPE and csize >= 36:
            (ns_idx, name_idx) = struct.unpack_from("<II", buf, off + 16)
            (attr_count,) = struct.unpack_from("<H", buf, off + 32)
            nm = pool.get_string(name_idx)
            if nm == "application":
                attr_start = off + 36
                # iterate attributes: each attr is 20 bytes
                android_ns_idx = None
                name_attr_index = None
                # ResXMLTree_attribute: ns(4), name(4), rawValue(4), typedValue: size(2), res0(1), dataType(1), data(4)
                for a in range(attr_count):
                    aoff = attr_start + a * 20
                    (ans, aname, araw) = struct.unpack_from("<III", buf, aoff)
                    (asize, ares0, adata_type, adata) = struct.unpack_from("<HBBI", buf, aoff + 12)
                    if adata_type == 0x03:  # TYPE_STRING
                        ns_string = pool.get_string(ans)
                        attr_name = pool.get_string(aname)
                        if ns_string == ANDROID_NAMESPACE and attr_name == "name":
                            name_attr_index = a
                            android_ns_idx = ans
                            break
                if name_attr_index is not None:
                    found = (off, attr_start, name_attr_index)
                    break
        if csize < 8:
            break
        off += csize

    if found is None:
        raise ValueError("application android:name attribute not found")

    app_off, attr_start, attr_idx = found
    aoff = attr_start + attr_idx * 20

    # append new string to pool
    new_idx = pool.append_utf8_string(new_name)

    # Since append_utf8_string mutated buf, offsets may have shifted? It inserted before string data, and also inserted 4 bytes in offsets array.
    # The buffer length changed. The absolute position of the attribute may have shifted because string pool chunk is at the beginning.
    # BUT the insertion happened at the string data region (after offsets array), so chunk header and offsets array shifted? No:
    # We inserted 4 bytes in the offsets array (at offset 28 + count*4). That shifted all subsequent bytes (including string data, and chunks after) by 4.
    # Then inserted string bytes at string data end, shifting everything after by len(entry).
    # Therefore all absolute positions after the insertion point shifted.
    # We cannot reuse old absolute offsets. We need re-find the application element after modifications.
    # Simpler: re-run parsing from the new buffer after each append.
    # To avoid complexity, we re-find now:
    # (We'll just re-start after mutation.)
    # Actually the attribute position in buffer changed. Let's recompute.

    # Recompute pool and search again:
    buf2 = pool.buf  # mutated buffer
    pool2 = StringPool(buf2, 8)
    # find application attr again
    off2 = 8 + pool2.chunk_size
    target = None
    while off2 + 8 <= len(buf2):
        (ctype2, cheader2, csize2) = struct.unpack_from("<HHI", buf2, off2)
        if ctype2 == RES_XML_START_ELEMENT_TYPE and csize2 >= 36:
            (ns_idx2, name_idx2) = struct.unpack_from("<II", buf2, off2 + 16)
            (attr_count2,) = struct.unpack_from("<H", buf2, off2 + 32)
            if pool2.get_string(name_idx2) == "application":
                attr_start2 = off2 + 36
                for a2 in range(attr_count2):
                    aoff2 = attr_start2 + a2 * 20
                    (ans2, aname2, araw2) = struct.unpack_from("<III", buf2, aoff2)
                    (asize2, ares0_2, adata_type2, adata2) = struct.unpack_from("<HBBI", buf2, aoff2 + 12)
                    if adata_type2 == 0x03:
                        if pool2.get_string(ans2) == ANDROID_NAMESPACE and pool2.get_string(aname2) == "name":
                            target = aoff2
                            break
                if target is not None:
                    break
        if csize2 < 8:
            break
        off2 += csize2

    if target is None:
        raise ValueError("application name attribute lost after mutation")

    # rewrite rawValue and typedValue.data to new_idx
    # rawValue is at target+8
    struct.pack_into("<I", buf2, target + 8, new_idx)
    # typedValue: data at target+16 (size=2,res0=1,datatype=1,data=4)
    struct.pack_into("<I", buf2, target + 16, new_idx)

    # update file size (header), and any chunk size? Only string pool chunk size already updated.
    old_file_size = len(axml_bytes)
    new_file_size = len(buf2)
    struct.pack_into("<I", buf2, 4, new_file_size)

    return bytes(buf2)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("usage: axml_modifier.py in.bin out.bin")
        sys.exit(1)
    raw = open(sys.argv[1], "rb").read()
    out = modify_application_name(raw, "r.k.app")
    open(sys.argv[2], "wb").write(out)
    print("OK: %d -> %d bytes" % (len(raw), len(out)))
