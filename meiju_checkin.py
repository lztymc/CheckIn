#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
美的美居 Lite 微信小程序 —— 签到脚本（已还原签名算法，可运行）

=== 签名算法（已逆向自 wxapkg 的 app-service.js，100% 坐实）===
请求头 `sign` / `regionSign` 计算方式（源：utils/util.js 的 getNewSign、
utils/requestService.js 的请求装配、miniprogram_npm/m-utilsdk/common/hmacEncode.js）：

  sign = HmacSHA256( apiKey + JSON.stringify(body) + random , hmacEncode[env] )
       apiKey        = config.apiKey[env]  -> prod: "prod_secret123@muc"
       body          = 请求体（与发送体完全一致，无空格，键顺序一致）
       random        = 毫秒时间戳（与 header random 同一值）
       hmacEncode[env]= 混淆后还原的 HMAC 密钥
                        prod: "PROD_VnoClJI9aikS8dyy"
                        sit : "SIT_4VjZdg19laDoIrut"

  regionSign = md5( accessToken + userRegion )
       userRegion = wx.getStorageSync("userRegion")，缺省 "0"

=== 端点（base = https://mp-prod.smartmidea.net/mas/v5/app/proxy）===
真实路径放在 query 参数 alias 里，抓包[1062]已坐实：
  - 提交签到    : /api/cms_api/activity-center-im-service/im-svr/im/game/page/meiJu/newSign
  - 签到状态查询: /api/cms_api/activity-center-im-service/im-svr/im/game/page/meiJu/newSign/query
  - 会员信息    : /api/mcsp_uc/mcsp-uc-member/member/getMemberInfo.do
提交与查询请求体一致：
  {"headParams":{"language":"CN","originSystem":"MCSP","timeZone":"","userCode":"",
                 "tenantCode":"","userKey":"","transactionId":""},"restParams":{}}

=== accessToken ===
需登录后获取、会过期。优先级：环境变量 MEIJU_TOKEN > config.json 的 accessToken > 脚本内占位。
获取方式：从已登录的「美的美居Lite」小程序（appid wxb12ff482a3185e46）本地存储
globalData.userData.mdata.accessToken 取得（可用微信开发者工具 / 抓包拿到）。

=== Bark 推送（可选）===
设置环境变量 BARK_DEVICE_KEY 后，签到成功 / 失败 / 今日已签到 都会推送通知到 Bark App。
- 两种填法都兼容：纯 device key（如 `AbC123DeF`），或 Bark App 复制的完整推送地址（如 `https://api.day.app/AbC123DeF`）。
- 未设置该功能自动跳过，不影响签到。

=== 青龙面板部署所需环境变量 ===
  BARK_DEVICE_KEY  必填(仅用于推送)  去 Bark App 复制 device key（或完整推送地址）
  MEIJU_TOKEN      必填(登录态)       从已登录小程序取 accessToken 填入；过期需更新
  MEIJU_REGION     可选,默认 "0"      一般无需修改

=== 用法 ===
  python meiju_checkin.py            # 会员信息 + 查询 + 签到
  python meiju_checkin.py --query    # 只查签到状态
  python meiju_checkin.py --no-sign-in  # 会员信息 + 查询（不提交签到）
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.request
import urllib.error

BASE = "https://mp-prod.smartmidea.net/mas/v5/app/proxy"

# ---- 环境相关密钥（逆向自 wxapkg，已确认）----
ENV = "prod"                       # prod / sit
API_KEY = {
    "prod": "prod_secret123@muc",
    "sit":  "sit_secret123@muc",
}
HMAC_KEY = {
    "prod": "PROD_VnoClJI9aikS8dyy",
    "sit":  "SIT_4VjZdg19laDoIrut",
}

HEADERS_STATIC = {
    "xweb_xhr": "1",
    "secretVersion": "1.0",
    "iotAppId": "901",
    "version": "9.0",
    "terminalId": "901-default",
    "refer": "pages/mytab/mytab",
    "content-type": "application/json",
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 "
        "MicroMessenger/7.0.20.1781 NetType/WIFI MiniProgramEnv/Windows "
        "WindowsWechat/WMPF XWEB/25122"
    ),
    "Referer": "https://servicewechat.com/wxb12ff482a3185e46/310/page-frame.html",
}

SIGN_SUBMIT_ALIAS = "/api/cms_api/activity-center-im-service/im-svr/im/game/page/meiJu/newSign"
SIGN_QUERY_ALIAS = SIGN_SUBMIT_ALIAS + "/query"
MEMBER_INFO_ALIAS = "/api/mcsp_uc/mcsp-uc-member/member/getMemberInfo.do"


def _read_token_file():
    """从接收端写入的 token 文件读取（NAS webhook 全自动模式）。
    路径：环境变量 MEIJU_TOKEN_FILE，否则脚本同目录的 meiju_token.txt。"""
    path = os.environ.get("MEIJU_TOKEN_FILE") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "meiju_token.txt")
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                t = f.read().strip()
            return t or None
    except Exception:
        pass
    return None


def load_config():
    """读取 ACCESS_TOKEN / USER_REGION / BARK_DEVICE_KEY。
    优先级：环境变量 MEIJU_TOKEN > token 文件(meiju_token.txt) > config.json > 占位。"""
    cfg = {}
    cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}
    token = (os.environ.get("MEIJU_TOKEN")
             or _read_token_file()
             or cfg.get("accessToken")
             or "T1wkf2x33g8w2qkmn")
    region = os.environ.get("MEIJU_REGION") or cfg.get("userRegion") or "0"
    bark_key = os.environ.get("BARK_DEVICE_KEY") or cfg.get("barkDeviceKey") or ""
    return token, region, bark_key


def compute_sign(api_key: str, hmac_key: str, body: dict, random_ms: int):
    """还原 getNewSign（POST 分支）。返回 (sign, region_sign)。"""
    # sign = HmacSHA256( apiKey + JSON.stringify(body) + random , hmacKey )
    # 注意：JSON.stringify 无空格，键顺序与发送体一致
    body_str = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    msg = api_key + body_str + str(random_ms)
    sign = hmac.new(hmac_key.encode("utf-8"), msg.encode("utf-8"),
                    hashlib.sha256).hexdigest()
    return sign


def compute_region_sign(access_token: str, user_region: str) -> str:
    return hashlib.md5((access_token + user_region).encode("utf-8")).hexdigest()


def bark_base_url(key: str):
    """兼容两种填法：纯 device key -> https://api.day.app/KEY；
    或用户直接填完整 URL（如从 Bark App 复制的推送地址）。"""
    if not key:
        return None
    key = key.strip()
    if key.startswith("http://") or key.startswith("https://"):
        return key.rstrip("/")
    return f"https://api.day.app/{key}"


def bark_push(device_key: str, title: str, body: str):
    """签到结果推送。device_key 为空时静默跳过（不影响签到）。"""
    if not device_key:
        return
    url = bark_base_url(device_key)
    if not url:
        return
    payload = json.dumps({"title": title, "body": body},
                         ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[Bark推送] HTTP {resp.status} {title}")
    except Exception as e:
        print(f"[Bark推送失败] {e}")


def _gunzip(data: bytes) -> bytes:
    import gzip
    try:
        return gzip.decompress(data)
    except Exception:
        return data


def call_proxy(alias: str, rest_params: dict = None, access_token: str = "",
               user_region: str = "0") -> dict:
    url = f"{BASE}?alias={alias}"
    random_ms = int(time.time() * 1000)
    body = {
        "headParams": {
            "language": "CN",
            "originSystem": "MCSP",
            "timeZone": "",
            "userCode": "",
            "tenantCode": "",
            "userKey": "",
            "transactionId": "",
        },
        "restParams": rest_params or {},
    }
    sign = compute_sign(API_KEY[ENV], HMAC_KEY[ENV], body, random_ms)
    region_sign = compute_region_sign(access_token, user_region)

    headers = dict(HEADERS_STATIC)
    headers.update({
        "accessToken": access_token,
        "random": str(random_ms),
        "sign": sign,
        "regionSign": region_sign,
    })

    data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            if resp.headers.get("Content-Encoding", "").lower() == "gzip":
                raw = _gunzip(raw)
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            if e.headers.get("Content-Encoding", "").lower() == "gzip":
                raw = _gunzip(raw)
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {"__http_error__": e.code, "__body__": raw.decode("utf-8", "replace")}
    except urllib.error.URLError as e:
        return {"__url_error__": str(e)}
    except Exception as e:
        return {"__error__": str(e)}


def query_sign_status(access_token: str, user_region: str) -> dict:
    return call_proxy(SIGN_QUERY_ALIAS, access_token=access_token, user_region=user_region)


def do_sign(access_token: str, user_region: str, bark_key: str = "", member: dict = None) -> dict:
    resp = call_proxy(SIGN_SUBMIT_ALIAS, access_token=access_token, user_region=user_region)
    code = (resp or {}).get("code")
    data = (resp or {}).get("data", {})
    if code != "000000":
        title = "美的美居签到失败"
        body = f"code={code}, msg={(resp or {}).get('msg')}"
        print(f"[{title}] {body}")
        bark_push(bark_key, title, body)
        return resp
    # 提交后再查一次最新状态，拿连签天数与积分
    st = query_sign_status(access_token, user_region)
    sdata = (st or {}).get("data") or {}
    cont = sdata.get("contRegisterNum")
    day_pts = sdata.get("dayRewardPoints")
    vip_pts = ((member or {}).get("data") or {}).get("vipPoint")
    extra = ""
    if cont is not None:
        extra += f"\n连签天数：{cont} 天"
    if day_pts is not None:
        extra += f"\n当前签到积分：{day_pts}"
    if vip_pts is not None:
        extra += f"\n会员总积分：{vip_pts}"
    if data.get("dayRewardResult") is True:
        pts = data.get("dayRewardPointValue")
        title = "美的美居签到成功"
        body = f"签到成功，本次获得积分：{pts}{extra}"
        print(f"[签到成功] 获得日间奖励 {pts} 分{extra}")
    else:
        title = "美的美居签到"
        body = f"今日已签到（或无需重复签到）{extra}"
        print(f"[签到结果] {body}")
    bark_push(bark_key, title, body)
    return resp


def get_member_info(access_token: str, user_region: str) -> dict:
    return call_proxy(MEMBER_INFO_ALIAS, rest_params={
        "sourceSys": "IOT",
        "userId": "1114375151587",
        "brand": 1,
        "mobile": "13140583697",
    }, access_token=access_token, user_region=user_region)


class _Tee:
    """把 stdout/stderr 同时镜像到日志文件，方便青龙等无终端环境排查。"""
    def __init__(self, *streams):
        self.streams = streams

    def write(self, obj):
        for s in self.streams:
            try:
                s.write(obj)
                s.flush()
            except Exception:
                pass

    def flush(self):
        for s in self.streams:
            try:
                s.flush()
            except Exception:
                pass


def _setup_tee():
    try:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "meiju_checkin.log")
        f = open(log_path, "a", encoding="utf-8")
        sys.stdout = _Tee(sys.stdout, f)
        sys.stderr = _Tee(sys.stderr, f)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--query", action="store_true", help="只查签到状态")
    ap.add_argument("--no-sign-in", action="store_true", help="不提交签到")
    args = ap.parse_args()

    token, region, bark_key = load_config()
    token_file = os.environ.get("MEIJU_TOKEN_FILE") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "meiju_token.txt")
    print(f"[诊断] python={sys.version.split()[0]} | BARK={'已配置' if bark_key else '未配置(不会推送)'} | TOKEN={'占位' if token == 'T1wkf2x33g8w2qkmn' else '已配置'} | token文件={'存在' if os.path.exists(token_file) else '无'}")
    if token == "T1wkf2x33g8w2qkmn":
        print("[警告] 使用的是占位 accessToken，很可能已过期；如返回 token 相关错误请替换。")
    if not bark_key:
        print("[警告] 未配置 BARK_DEVICE_KEY，签到结果不会推送到 Bark。")

    if args.query:
        print("查询签到状态:", json.dumps(query_sign_status(token, region), ensure_ascii=False))
        return

    member = get_member_info(token, region)
    status = query_sign_status(token, region)
    print("会员信息:", json.dumps(member, ensure_ascii=False))
    print("签到状态:", json.dumps(status, ensure_ascii=False))
    if not args.no_sign_in:
        do_sign(token, region, bark_key, member=member)


if __name__ == "__main__":
    _setup_tee()
    main()
