#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
提取「美的美居Lite」小程序主包里的 app-service.js（含签到签名算法）。
关键技巧：V1MMWX 用 PBKDF2+AES-CBC，但 CBC 解密只有第 0 块依赖 IV；
第 1 块及之后只依赖密钥。本构建 IV 是版本私有常量，但我们不需要它——
直接用正确密钥解密后，plain[16:] 已是正确明文(wxapkg 索引与数据区)，
从偏移 16 解析索引即可定位并提取文件，完全绕开 IV。
"""
import os, hashlib, struct, brotli, zlib

WXID = "wxb12ff482a3185e46"
SRC = r"C:\Users\C23\AppData\Roaming\Tencent\xwechat\radium\users\21fc0038be0a0dd4139a5a34e19f22db\applet\packages\wxb12ff482a3185e46\310\__APP__.wxapkg"
OUT = r"C:\Users\C23\Documents\mx\美的美居\wxapkg_decrypted"
os.makedirs(OUT, exist_ok=True)

def unpad(b):
    if b and 1 <= b[-1] <= 16:
        return b[:-b[-1]]
    return b

def main():
    data = open(SRC, "rb").read()
    assert data[:6] == b"V1MMWX"
    key = hashlib.pbkdf2_hmac("sha1", WXID.encode(), b"saltiest", 1000, 32)
    iv = b"the iv: 16 bytes"  # 仅用于解密；第0块会有偏差，但我们不用它
    from Crypto.Cipher import AES
    aes_block = AES.new(key, AES.MODE_CBC, iv).decrypt(data[6:6 + 1024])
    xorkey = ord(WXID[-2])
    rest = bytes(b ^ xorkey for b in data[6 + 1024:])

    best = None
    for do_unpad in (True, False):
        plain = unpad(aes_block) + rest if do_unpad else aes_block + rest
        # 从偏移 16(索引起点) 解析
        files = []
        pos = 16
        ok = True
        for _ in range(5000):
            try:
                nl, = struct.unpack("<I", plain[pos:pos + 4]); pos += 4
                if nl <= 0 or nl > 4096:
                    ok = False; break
                name = plain[pos:pos + nl].decode("utf-8", "replace"); pos += nl
                foff, fsize = struct.unpack("<II", plain[pos:pos + 8]); pos += 8
                files.append((name, foff, fsize))
                if "app-service" in name:
                    break
            except Exception:
                ok = False; break
        if ok and files:
            print(f"[unpad={do_unpad}] 解析到 {len(files)} 个文件，含 app-service:",
                  [n for n, _, _ in files if 'app-service' in n][:5])
            best = (plain, files)
            if any("app-service" in n for n, _, _ in files):
                break
    if not best:
        print("索引解析失败")
        return
    plain, files = best

    def decompress(block):
        for c in (block, block[1:], block[2:]):
            for fn in (brotli.decompress, zlib.decompress):
                try:
                    d = fn(c)
                    if b"function" in d[:500] or b"var " in d[:500] or b"require" in d[:500] or d[:1] in b"{[(/\"":
                        return d
                except Exception:
                    pass
        return block

    for name, foff, fsize in files:
        if "app-service" not in name:
            continue
        block = plain[foff:foff + fsize]
        js = decompress(block)
        try:
            js.decode("utf-8")
            ext = ".js"
        except Exception:
            ext = ".js.bin"
        # 文件名清理
        safe = name.replace("/", "_").replace("\\", "_")
        path = os.path.join(OUT, "APP_SERVICE_" + safe + ext)
        open(path, "wb").write(js)
        print(f"已提取 {name} -> {path} ({len(js)} bytes)")
        # 立即搜签名相关片段
        try:
            txt = js.decode("utf-8", "replace")
        except Exception:
            txt = ""
        for kw in ("sign", "regionSign", "md5", "sha256", "sha1", "secretVersion", "genSign", "signature"):
            idx = txt.lower().find(kw.lower())
            if idx != -1:
                snip = txt[max(0, idx - 80):idx + 200]
                print(f"  >>> 命中 {kw} @ {idx}:\n      {snip!r}")

if __name__ == "__main__":
    main()
