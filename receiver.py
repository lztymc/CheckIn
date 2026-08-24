#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
美的美居 token 接收端（极空间 NAS 常驻服务，零第三方依赖）

作用：
  接收 Loon / Shadowrocket 抓到的 accessToken（即签到脚本需要的 MEIJU_TOKEN），
  写入 token 文件，供 meiju_checkin.py 自动读取。实现「token 过期全自动续」。

运行（在 NAS 上，建议放在 meiju_checkin.py 同目录）：
  python3 receiver.py
  # 后台常驻：
  nohup python3 receiver.py > receiver.log 2>&1 &

环境变量（均可选）：
  MEIJU_RECEIVER_PORT  监听端口，默认 18910
  MEIJU_TOKEN_FILE     token 写入路径，默认 ./meiju_token.txt（即脚本同目录）
  MEIJU_HOOK_SECRET    共享密钥；留空=不校验。建议设置一个，Loon 端用 &secret= 带上

Loon / Shadowrocket 推送地址：
  http://<NAS局域网IP>:<PORT>/meiju_token?token=<URL编码后的token>[&secret=<密钥>]
  也支持 POST body：token=<URL编码后的token>
"""
import http.server
import os
import sys
import urllib.parse
from datetime import datetime

PORT = int(os.environ.get("MEIJU_RECEIVER_PORT", "18910"))
TOKEN_FILE = os.environ.get(
    "MEIJU_TOKEN_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "meiju_token.txt"),
)
SECRET = os.environ.get("MEIJU_HOOK_SECRET", "")  # 留空=不校验


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, msg):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(msg.encode("utf-8"))

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        if p.path in ("/", "/health"):
            self._send(200, "meiju token receiver ok")
            return
        self._send(404, "not found")

    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        if p.path != "/meiju_token":
            self._send(404, "not found")
            return
        q = urllib.parse.parse_qs(p.query)
        if SECRET:
            if q.get("secret", [""])[0] != SECRET:
                self._send(403, "bad secret")
                return
        token = (q.get("token") or [""])[0]
        if not token:
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
            except Exception:
                length = 0
            if length:
                body = self.rfile.read(length).decode("utf-8", "replace")
                try:
                    token = (urllib.parse.parse_qs(body).get("token") or [""])[0]
                except Exception:
                    token = ""
        token = (token or "").strip()
        if not token:
            self._send(400, "empty token")
            return
        try:
            parent = os.path.dirname(os.path.abspath(TOKEN_FILE))
            os.makedirs(parent, exist_ok=True)
            with open(TOKEN_FILE, "w", encoding="utf-8") as f:
                f.write(token)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{ts}] token updated len={len(token)}: {token[:6]}****{token[-4]}",
                  flush=True)
            self._send(200, "ok")
        except Exception as e:  # noqa
            self._send(500, f"write failed: {e}")

    def log_message(self, fmt, *args):
        pass  # 静默默认访问日志


def main():
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"meiju token receiver listening on 0.0.0.0:{PORT}", flush=True)
    print(f"token file: {TOKEN_FILE}", flush=True)
    print("secret: " + ("enabled" if SECRET else "DISABLED (建议设置 MEIJU_HOOK_SECRET)"),
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("bye", flush=True)


if __name__ == "__main__":
    main()
