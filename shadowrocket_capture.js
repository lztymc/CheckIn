// ============================================================
// 美的美居（Lite 小程序 / App）accessToken 自动抓取脚本
// 平台：Shadowrocket（小火箭）脚本
// 事件：HTTP 请求（推荐）或 HTTP 响应
// URL 匹配正则：^https?:\/\/.*smartmidea\.net
// 前置条件：
//   1) 小火箭 → 配置 → 证书 → 安装，并在 iOS
//      「设置 → 通用 → VPN与设备管理」安装描述文件，
//      再「设置 → 关于本机 → 证书信任设置」信任小火箭 CA。
//   2) 小火箭 → 配置 → 解密 → 开启，并添加主机名 *smartmidea.net
//      （覆盖 mp-prod / account 等全部子域）。
// 作用：拦截美的美居任意 API 请求/响应，提取最新的
//      accessToken（即签到脚本所需的 MEIJU_TOKEN），
//      存入小火箭本地 $prefs（键 MEIJU_TOKEN），并弹通知。
// 如需自动同步到青龙，见文末「青龙联动」注释。
// ============================================================

const KEY = "MEIJU_TOKEN";

function pickToken() {
    // —— 1) 请求头（app 主动携带的当前有效 token，最可靠）——
    if (typeof $request !== "undefined" && $request.headers) {
        const h = $request.headers || {};
        const cand = ["accessToken", "accesstoken", "Authorization", "token", "x-access-token"];
        for (const k of cand) {
            let v = h[k];
            if (v == null) continue;
            if (Array.isArray(v)) v = v[0];
            v = String(v).trim();
            if (/^bearer\s+/i.test(v)) v = v.slice(v.indexOf(" ") + 1);
            if (v) return v;
        }
        // 请求体里也可能带 token
        if ($request.body) {
            try {
                const b = JSON.parse($request.body);
                const t = b?.headParams?.accessToken || b?.data?.accessToken || b?.accessToken;
                if (t) return String(t);
            } catch (e) {}
        }
    }
    // —— 2) 响应体（登录 / 刷新接口会下发新 token）——
    if (typeof $response !== "undefined" && $response.body) {
        try {
            const b = JSON.parse($response.body);
            const t = b?.data?.accessToken || b?.accessToken;
            if (t) return String(t);
        } catch (e) {}
    }
    return "";
}

(function () {
    const token = pickToken();
    if (!token) { $done({}); return; }

    const old = ($prefs && $prefs.valueForKey) ? $prefs.valueForKey(KEY) : "";
    if (old === token) { $done({}); return; }

    if ($prefs && $prefs.setValueForKey) $prefs.setValueForKey(token, KEY);

    const preview = token.slice(0, 6) + "****" + token.slice(-4);
    if (typeof $notify === "function") $notify("美的美居", "Token 已抓取/更新", preview);

    // —— 青龙联动 ——
    // 方式一：推到 Bark，你在手机上看到后手动复制进青龙环境变量。
    // if (typeof $httpClient !== "undefined") {
    //     $httpClient.post(
    //         { url: "https://api.day.app/你的BarkKey/美的美居Token已更新/" + encodeURIComponent(token) },
    //         function () {}
    //     );
    // }
    // 方式二：POST 到家里 NAS 接收端（全自动）。把 NAS局域网IP 换成你极空间的局域网 IP，
    //         端口与 receiver.py 的 MEIJU_RECEIVER_PORT 一致（默认 18910）。
    if (typeof $httpClient !== "undefined") {
        var hookUrl = "http://NAS局域网IP:18910/meiju_token?token=" + encodeURIComponent(token);
        // 若 receiver.py 设了 MEIJU_HOOK_SECRET，取消下一行注释并填入同一密钥：
        // hookUrl += "&secret=你的密钥";
        $httpClient.post({ url: hookUrl }, function () {});
    }

    $done({});
})();
