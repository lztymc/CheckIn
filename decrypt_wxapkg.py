#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
解密并解包「美的美居Lite」微信小程序(wxid=wxb12ff482a3185e46)的加密 wxapkg。
PC 微信 V1MMWX 双重加密：
  1) key = PBKDF2(wxid, salt="saltiest", 1000, SHA1, 32)
  2) 文件 [6:1030] 共 1024 字节 -> AES-CBC 解密 (IV="the iv: 16 bytes")
  3) 文件 [1030:] -> 逐字节 XOR，密钥 = wxid 倒数第二字符的 ASCII
解密后得到明文 wxapkg，再解析索引、启发式解压各文件，提取 app-service.js 等待审。
"""
import os, hashlib, struct, brotli, zlib

WXID = "wxb12ff482a3185e46"
SRC = r"C:\Users\C23\AppData\Roaming\Tencent\xwechat\radium\users\21fc0038be0a0dd4139a5a34e19f22db\applet\packages\wxb12ff482a3185e46\310\__APP__.wxapkg"
OUT_DIR = r"C:\Users\C23\Documents\mx\美的美居\wxapkg_decrypted"

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    data = open(SRC, "rb").read()
    assert data[:6] == b"V1MMWX", "不是 V1MMWX 加密包"
    print("原始大小:", len(data))

    key = hashlib.pbkdf2_hmac("sha1", WXID.encode(), b"saltiest", 1000, 32)
    iv = b"the iv: 16 bytes"
    print("key(hex前8):", key[:8].hex(), " iv:", iv)

    from Crypto.Cipher import AES
    aes = AES.new(key, AES.MODE_CBC, iv)
    aes_block = aes.decrypt(data[6:6 + 1024])
    xorkey = ord(WXID[-2])
    rest = bytes(b ^ xorkey for b in data[6 + 1024:])
    plain = aes_block + rest
    print("明文 wxapkg 头:", plain[:4].hex(), "(应为 be ef 98 76)")
    assert plain[:4] == b"\xbe\xef\x98\x76", "解密失败"
    open(os.path.join(OUT_DIR, "__APP__plain.wxapkg"), "wb").write(plain)
    print("已写解密容器 ->", os.path.join(OUT_DIR, "__APP__plain.wxapkg"))

    magic, ver, fileCount, idxLen = struct.unpack("<4sIII", plain[:16])
    print("version=", ver, "fileCount=", fileCount, "indexLen=", idxLen)
    off = 16
    files = []
    for _ in range(fileCount):
        nl, = struct.unpack("<I", plain[off:off + 4]); off += 4
        name = plain[off:off + nl].decode("utf-8", "replace"); off += nl
        foff, fsize = struct.unpack("<II", plain[off:off + 8]); off += 8
        files.append((name, foff, fsize))

    def decompress(block):
        for c in (block, block[1:], block[2:]):
            for fn in (brotli.decompress, zlib.decompress):
                try:
                    d = fn(c)
                    head = d[:200]
                    if (head[:1] in (b"{", b"[", b"(", b"/", b"v", b"f", b"i", b'"', b" ")
                            or b"function" in head or b"var " in head or b"require" in head):
                        return d
                except Exception:
                    pass
        return block

    for name, foff, fsize in files:
        block = plain[foff:foff + fsize]
        txt = decompress(block)
        try:
            txt.decode("utf-8")
            ext = ".js" if (name.endswith(".js") or "service" in name) else ".bin"
        except Exception:
            ext = ".bin"
        safe = name.replace("/", "_").replace("\\", "_")
        path = os.path.join(OUT_DIR, safe + ("" if safe.endswith(".js") else ext))
        with open(path, "wb") as f:
            f.write(txt)
    print("共提取文件:", len(files))
    jss = [n for n, _, _ in files if n.endswith(".js") or "service" in n]
    print("JS/Service 文件:", jss)

if __name__ == "__main__":
    main()
