# -*- coding: utf-8 -*-
"""
药商帮 · 平台数据服务端 v5（可上线加固版）
================================================
平台服务商模式：供应商加盟入驻 + 平台审核 + 药店采购。
v5（相对 v4）：
  - 修改密码：POST /api/change-pwd（原密校验、新密≥4位、审计）
  - 经营分析报表：销售趋势 / 品种分析 / 店铺流量 / 汇总卡片
  - 评价复购：POST /api/review、GET /api/review（供应商收评、买家可查）
  - 订单状态流转：POST /api/order/status（供应商发货/完成/取消）
  - 站内信：GET /api/notices、POST /api/notices/send、POST /api/notices/read
  - 优惠券数据随市场聚合下发（供应商端 CRUD 走 /api/data/coupons）
v4 基线：证照中心跨店铺聚合（含 shopName）、会话 12h 滑动续期、登录 5 次失败锁 10 分钟、
  数据自动备份、审计日志、CORS 白名单、结算打款幂等、默认平台账号 admin/admin123。

运行：python server.py [--port 8000] [--host 0.0.0.0] [--data data/state.json]
               [--backup-interval 60] [--backup-keep 50] [--audit data/audit.log]
               [--allow-origin https://你的域名]
API（全部 JSON，与 v3/v4 兼容）：
  账号 / 入驻
    POST /api/apply               入驻申请 {username,password,shopName,contact,phone,license,address}
    POST /api/login               登录     {username,password} -> {ok,role,token,shopId,shopName,reason}
    GET  /api/session?token=      会话校验
    POST /api/reg-buyer           药店注册 {username,password,shopName,contact,phone}
    POST /api/change-pwd?token=   {oldPwd,newPwd} 修改当前账号密码
  平台管理
    GET  /api/platform/apply?token=          待审核/全部入驻申请
    POST /api/platform/audit?token=          {applyId,pass,reason} 审核通过则开店+建号
    GET  /api/platform/overview?token=       平台总览
    GET  /api/platform/shops?token=          店铺列表
    PUT  /api/platform/cfg?token=            {commissionRate} 佣金率
    GET  /api/platform/cfg?token=
  业务（token 鉴权，按当前店铺分桶）
    GET  /api/data/<col>?token=              当前店铺集合
    PUT  /api/data/<col>?token=              覆盖当前店铺集合
  采购端
    GET  /api/market?token=                  全部在营店铺商品聚合（含优惠券）
    GET  /api/market/orders?token=           聚合该药店的采购订单
  结算
    POST /api/settle/submit?token=           {orderIds,period} 供应商生成结算单
    GET  /api/settle?token=                  供应商看自己/平台看全部
    POST /api/settle/pay?token=              {settleId} 平台确认打款
  合规
    GET  /api/compliance?token=              供应商看自己证照/平台聚合全部
  订单状态
    POST /api/order/status?token=            {orderId,status} 供应商发货/完成/取消
  经营分析
    GET  /api/report/overview?token=         汇总卡片（平台全平台/供应商本店）
    GET  /api/report/sales?token=            销售趋势（按日订单额/订单数）
    GET  /api/report/products?token=         品种分析（商品销量/销售额/单数）
    GET  /api/report/traffic?token=          店铺流量（店铺维度订单/买家/销售额/复购率）
  评价
    POST /api/review?token=                  {orderId,rating,content} 药店评价
    GET  /api/review?token=                  供应商看本店评价/药店看自己评价
  站内信
    GET  /api/notices?token=                 当前用户可见站内信（含 unread 数）
    POST /api/notices/send?token=            {title,content,to} 平台发送
    POST /api/notices/read?token=            {noticeId} 标记已读
生产提示：HTTPS 由 Nginx/Caddy 反向代理终结（见部署文档），本服务无需自持证书。
"""
import json, os, sys, threading, time, hashlib, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, unquote, parse_qs

DEFAULT_PORT = 8000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "data", "state.json")

_lock = threading.Lock()
_cache = {}
_sessions = {}   # token -> {username, role, shopId, exp}
_login_fail = {} # username -> {cnt, lock}
_dirty = False
_last_backup = 0.0

ROLE_LABEL = {"platform": "平台运营", "supplier": "供应商", "buyer": "药店"}

# 上线加固参数（由 main() 解析命令行覆盖）
SESSION_TTL = 12 * 3600        # token 有效 12 小时
LOCK_MAX = 5                   # 连续失败 5 次锁定
LOCK_SECONDS = 600             # 锁定 10 分钟
BACKUP_INTERVAL = 60           # 备份节流（秒）
BACKUP_KEEP = 50               # 保留最近快照份数
AUDIT_FILE = None              # 审计日志路径，None=关闭
ALLOWED_ORIGINS = ["*"]        # CORS 白名单
HOST = "0.0.0.0"


def _new_state():
    return {"ac_accounts": [], "ac_apply": [], "shops": [],
            "settles": [], "sys_cfg": {"commissionRate": 0.05},
            "notices": [], "data": {}}


def _load():
    global _cache, _dirty
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            _cache = json.load(f)
    except Exception:
        _cache = {}
    base = _new_state()
    for k in base:
        if k not in _cache:
            _cache[k] = base[k]
    if not isinstance(_cache["data"], dict):
        _cache["data"] = {}
    # 默认平台运营账号（初始引导用）：admin / admin123，首次登录后建议改密
    if not any(a.get("role") == "platform" for a in _cache.get("ac_accounts", [])):
        _cache["ac_accounts"].append({"id": "ACC-ADMIN", "username": "admin",
                                      "passwordHash": _h("admin123"), "role": "platform",
                                      "shopId": None, "name": "平台运营中心",
                                      "contact": "", "phone": "", "status": "active",
                                      "joinTime": time.strftime("%Y-%m-%d %H:%M:%S")})
        _dirty = True
    print("[server] loaded. shops:", len(_cache.get("shops", [])),
          "accounts:", len(_cache.get("ac_accounts", [])),
          "applies:", len(_cache.get("ac_apply", [])), flush=True)


def _save():
    global _dirty
    try:
        os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(_cache, f, ensure_ascii=False, indent=1)
        _dirty = False
        _snapshot()
    except Exception as e:
        print("[server] save error:", e, flush=True)


def _snapshot():
    """落盘后写时间戳备份，保留最近 BACKUP_KEEP 份"""
    global _last_backup
    now = time.time()
    if now - _last_backup < BACKUP_INTERVAL:
        return
    _last_backup = now
    try:
        bd = os.path.join(os.path.dirname(DATA_FILE), "backups")
        os.makedirs(bd, exist_ok=True)
        name = "state-" + time.strftime("%Y%m%d-%H%M%S") + ".json"
        with open(os.path.join(bd, name), "w", encoding="utf-8") as f:
            json.dump(_cache, f, ensure_ascii=False, indent=1)
        files = sorted(os.listdir(bd))
        while len(files) > BACKUP_KEEP:
            os.remove(os.path.join(bd, files[0]))
            files.pop(0)
    except Exception as e:
        print("[server] backup error:", e, flush=True)


def _bg_flush():
    def run():
        while True:
            time.sleep(3)
            global _dirty
            if _dirty:
                _save()
    threading.Thread(target=run, daemon=True).start()


def _h(pw):
    return hashlib.sha256((pw or "").encode("utf-8")).hexdigest()


def _audit(action, user="", detail=""):
    """审计日志：动作 / 用户 / 详情，一行一条"""
    if not AUDIT_FILE:
        return
    try:
        os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write("%s [%s] %s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                         action, user or "-", detail or "-"))
    except Exception:
        pass


def _find_account(username):
    for a in _cache.get("ac_accounts", []):
        if a.get("username") == username:
            return a
    return None


def _apply_by_id(aid):
    for a in _cache.get("ac_apply", []):
        if a.get("id") == aid:
            return a
    return None


def _shop_by_id(sid):
    for s in _cache.get("shops", []):
        if s.get("shopId") == sid:
            return s
    return None


def _account_by_shop(sid):
    for a in _cache.get("ac_accounts", []):
        if a.get("shopId") == sid and a.get("role") == "supplier":
            return a
    return None


def _new_token(user, role, shopId=None):
    t = secrets.token_hex(16)
    _sessions[t] = {"username": user, "role": role, "shopId": shopId,
                    "exp": time.time() + SESSION_TTL}
    return t


def _authed(q):
    t = (q.get("token") or [""])[0]
    s = _sessions.get(t)
    if not s:
        return None
    if time.time() > s["exp"]:
        _sessions.pop(t, None)
        return None
    s["exp"] = time.time() + SESSION_TTL   # 滑动续期
    return s


def _visible_orders(sess):
    """按会话角色返回可见订单流 [(order, shopId, shopName)]"""
    out = []
    for sid, bucket in _cache["data"].items():
        if sess["role"] != "platform" and sid != sess.get("shopId"):
            continue
        shop = _shop_by_id(sid)
        for o in bucket.get("orders", []):
            if sess["role"] == "buyer":
                if o.get("buyerShop") != sess.get("shopId") and o.get("store") != sess.get("name"):
                    continue
            out.append((o, sid, (shop or {}).get("shopName", "")))
    return out


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body=None, ctype="application/json; charset=utf-8"):
        """统一响应出口：先 send_response 再发头，避免 HTTP/0.9 坏状态行"""
        origin = self.headers.get("Origin", "")
        if origin == "":            # 非浏览器请求（curl/健康检查/服务端间调用）不做 CORS 校验
            allowed = True
            acao = "*"
        else:
            allowed = ("*" in ALLOWED_ORIGINS or origin in ALLOWED_ORIGINS)
            acao = "*" if "*" in ALLOWED_ORIGINS else origin
        if not allowed:
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(b'{"ok":false,"error":"origin not allowed"}')
            return
        self.send_response(code)
        self.send_header("Access-Control-Allow-Origin", acao)
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body) if body is not None else 0))
        self.end_headers()
        if body is not None:
            self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b""
            return json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            return None

    def do_OPTIONS(self):
        self._send(204)

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        q = parse_qs(u.query)
        with _lock:
            if path == "/api/health":
                self._json({"ok": True, "service": "yaoshangbang-platform-v5",
                            "time": time.strftime("%Y-%m-%d %H:%M:%S")})
            elif path == "/api/session":
                s = _authed(q)
                self._json({"ok": bool(s), "user": (s or {}).get("username"),
                            "role": (s or {}).get("role"), "shopId": (s or {}).get("shopId"),
                            "roleLabel": ROLE_LABEL.get((s or {}).get("role"), "")})
            elif path == "/api/platform/cfg":
                s = _authed(q)
                if not s:
                    self._json({"ok": False, "error": "未登录"}, 401); return
                if s["role"] not in ("platform", "supplier"):
                    self._json({"ok": False, "error": "无权限"}, 403); return
                self._json({"ok": True, "cfg": _cache["sys_cfg"]})
            elif path == "/api/platform/apply":
                s = _authed(q)
                if not s or s["role"] != "platform":
                    self._json({"ok": False, "error": "无权限"}, 403); return
                self._json({"ok": True, "list": _cache["ac_apply"]})
            elif path == "/api/platform/shops":
                s = _authed(q)
                if not s or s["role"] != "platform":
                    self._json({"ok": False, "error": "无权限"}, 403); return
                self._json({"ok": True, "list": _cache["shops"]})
            elif path == "/api/platform/overview":
                s = _authed(q)
                if not s or s["role"] != "platform":
                    self._json({"ok": False, "error": "无权限"}, 403); return
                self._json({"ok": True, "overview": _overview()})
            elif path == "/api/settle":
                s = _authed(q)
                if not s:
                    self._json({"ok": False, "error": "未登录"}, 401); return
                if s["role"] == "platform":
                    self._json({"ok": True, "list": _cache["settles"]})
                else:
                    mine = [x for x in _cache["settles"] if x.get("shopId") == s["shopId"]]
                    self._json({"ok": True, "list": mine})
            elif path == "/api/compliance":
                s = _authed(q)
                if not s:
                    self._json({"ok": False, "error": "未登录"}, 401); return
                if s["role"] == "platform":
                    rows = []
                    for sid, bucket in _cache["data"].items():
                        for rec in bucket.get("compliance", []):
                            rows.append(dict(rec, shopId=sid, shopName=(_shop_by_id(sid) or {}).get("shopName", "")))
                    self._json({"ok": True, "list": rows})
                else:
                    bucket = _cache["data"].get(s["shopId"], {})
                    self._json({"ok": True, "list": bucket.get("compliance", [])})
            elif path.startswith("/api/data/") and len(path) > len("/api/data/") and path != "/api/data/all":
                col = unquote(path[len("/api/data/"):])
                s = _authed(q)
                if not s:
                    self._json({"ok": False, "error": "未登录"}, 401); return
                bucket = _cache["data"].get(s["shopId"], {})
                self._json({"ok": True, "arr": bucket.get(col, [])})
            elif path == "/api/data/all":
                s = _authed(q)
                if not s:
                    self._json({"ok": False, "error": "未登录"}, 401); return
                bucket = _cache["data"].get(s["shopId"], {})
                self._json({"ok": True, "bucket": bucket})
            elif path == "/api/market":
                s = _authed(q)
                if not s:
                    self._json({"ok": False, "error": "未登录"}, 401); return
                rows, coupons = [], []
                for sid, bucket in _cache["data"].items():
                    shop = _shop_by_id(sid)
                    if not shop or shop.get("status") != "active":
                        continue
                    for p in bucket.get("products", []):
                        rows.append(dict(p, shopId=sid, shopName=shop.get("shopName", "")))
                    for c in bucket.get("coupons", []):
                        coupons.append(dict(c, shopId=sid, shopName=shop.get("shopName", "")))
                self._json({"ok": True, "list": rows, "coupons": coupons})
            elif path == "/api/market/orders":
                s = _authed(q)
                if not s or s["role"] != "buyer":
                    self._json({"ok": False, "error": "无权限"}, 403); return
                rows = []
                for sid, bucket in _cache["data"].items():
                    for o in bucket.get("orders", []):
                        # 只返回本药店提交的订单，避免跨药店越权
                        if o.get("buyerShop") != s["shopId"] and o.get("store") != s.get("name"):
                            continue
                        rows.append(dict(o, shopId=sid))
                self._json({"ok": True, "list": rows})
            elif path == "/api/report/overview":
                s = _authed(q)
                if not s:
                    self._json({"ok": False, "error": "未登录"}, 401); return
                self._json({"ok": True, "report": _report_overview(s)})
            elif path == "/api/report/sales":
                s = _authed(q)
                if not s:
                    self._json({"ok": False, "error": "未登录"}, 401); return
                self._json({"ok": True, "rows": _report_sales(s)})
            elif path == "/api/report/products":
                s = _authed(q)
                if not s:
                    self._json({"ok": False, "error": "未登录"}, 401); return
                self._json({"ok": True, "rows": _report_products(s)})
            elif path == "/api/report/traffic":
                s = _authed(q)
                if not s:
                    self._json({"ok": False, "error": "未登录"}, 401); return
                self._json({"ok": True, "rows": _report_traffic(s)})
            elif path == "/api/review":
                s = _authed(q)
                if not s:
                    self._json({"ok": False, "error": "未登录"}, 401); return
                if s["role"] == "buyer":
                    mine = []
                    for sid, bucket in _cache["data"].items():
                        for rv in bucket.get("reviews", []):
                            if rv.get("buyerShop") == s["shopId"] or rv.get("buyer") == s["username"]:
                                mine.append(dict(rv, shopId=sid, shopName=(_shop_by_id(sid) or {}).get("shopName", "")))
                    self._json({"ok": True, "list": mine})
                else:
                    bucket = _cache["data"].get(s["shopId"], {})
                    self._json({"ok": True, "list": bucket.get("reviews", [])})
            elif path == "/api/notices":
                s = _authed(q)
                if not s:
                    self._json({"ok": False, "error": "未登录"}, 401); return
                visible, unread = [], 0
                for n in _cache.get("notices", []):
                    if not _notice_visible(n, s):
                        continue
                    visible.append(n)
                    if s["username"] not in n.get("readBy", []):
                        unread += 1
                visible.sort(key=lambda x: x.get("time", ""), reverse=True)
                self._json({"ok": True, "list": visible, "unread": unread})
            else:
                self._json({"ok": False, "error": "not found"}, 404)

    def do_POST(self):
        global _dirty
        u = urlparse(self.path)
        path = u.path
        q = parse_qs(u.query)
        data = self._body()
        if data is None:
            self._json({"ok": False, "error": "bad json"}, 400); return
        with _lock:
            if path == "/api/apply":
                username = (data.get("username") or "").strip()
                if not username or not data.get("password") or not data.get("shopName"):
                    self._json({"ok": False, "error": "资料不完整"}); return
                if _find_account(username):
                    self._json({"ok": False, "error": "用户名已存在"}); return
                rec = {"id": "AP" + str(int(time.time() * 1000)),
                       "username": username, "passwordHash": _h(data.get("password")),
                       "shopName": (data.get("shopName") or "").strip(),
                       "contact": (data.get("contact") or "").strip(),
                       "phone": (data.get("phone") or "").strip(),
                       "license": (data.get("license") or "").strip(),
                       "address": (data.get("address") or "").strip(),
                       "applyTime": time.strftime("%Y-%m-%d %H:%M:%S"),
                       "status": "pending", "reason": ""}
                _cache["ac_apply"].insert(0, rec); _dirty = True
                _audit("apply", username, "提交入驻申请 " + rec["shopName"])
                self._json({"ok": True, "applyId": rec["id"]})
            elif path == "/api/reg-buyer":
                username = (data.get("username") or "").strip()
                if not username or not data.get("password") or not data.get("shopName"):
                    self._json({"ok": False, "error": "资料不完整"}); return
                if _find_account(username):
                    self._json({"ok": False, "error": "用户名已存在"}); return
                sid = "BYR" + secrets.token_hex(3)
                _cache["ac_accounts"].append({"id": "ACC" + secrets.token_hex(3),
                                              "username": username, "passwordHash": _h(data.get("password")),
                                              "role": "buyer", "shopId": sid,
                                              "name": (data.get("shopName") or "").strip(),
                                              "contact": (data.get("contact") or "").strip(),
                                              "phone": (data.get("phone") or "").strip(),
                                              "status": "active", "joinTime": time.strftime("%Y-%m-%d %H:%M:%S")})
                _dirty = True
                _audit("reg-buyer", username, "药店注册 " + (data.get("shopName") or ""))
                self._json({"ok": True})
            elif path == "/api/change-pwd":
                s = _authed(q)
                if not s:
                    self._json({"ok": False, "error": "未登录"}, 401); return
                oldPwd = data.get("oldPwd") or ""
                newPwd = data.get("newPwd") or ""
                if len(newPwd) < 4:
                    self._json({"ok": False, "error": "新密码至少 4 位"}); return
                acc = _find_account(s["username"])
                if not acc or acc.get("passwordHash") != _h(oldPwd):
                    self._json({"ok": False, "error": "原密码不正确"}); return
                acc["passwordHash"] = _h(newPwd)
                _dirty = True
                _audit("change-pwd", s["username"], "修改密码")
                self._json({"ok": True})
            elif path == "/api/login":
                username = (data.get("username") or "").strip()
                now = time.time()
                fl = _login_fail.get(username)
                if fl and fl.get("lock") and now < fl["lock"]:
                    remain = int(fl["lock"] - now)
                    self._json({"ok": False, "error": "尝试次数过多，请 %d 秒后再试" % remain}); return
                acc = _find_account(username)
                if not acc or acc.get("passwordHash") != _h(data.get("password")):
                    cnt = (fl or {}).get("cnt", 0) + 1
                    if cnt >= LOCK_MAX:
                        _login_fail[username] = {"cnt": 0, "lock": now + LOCK_SECONDS}
                        _audit("login-fail", username, "连续失败 %d 次，锁定 %d 分钟" % (LOCK_MAX, LOCK_SECONDS // 60))
                        self._json({"ok": False, "error": "尝试次数过多，账号已锁定 10 分钟"}); return
                    _login_fail[username] = {"cnt": cnt}
                    self._json({"ok": False, "error": "账号或密码错误（剩余尝试 %d 次）" % (LOCK_MAX - cnt)}); return
                if acc.get("status") != "active":
                    self._json({"ok": False, "error": "账号未激活"}); return
                _login_fail.pop(username, None)
                t = _new_token(username, acc["role"], acc.get("shopId"))
                _audit("login", username, acc["role"])
                self._json({"ok": True, "token": t, "role": acc["role"],
                            "roleLabel": ROLE_LABEL.get(acc["role"]),
                            "shopId": acc.get("shopId"),
                            "shopName": acc.get("name"),
                            "name": acc.get("name")})
            elif path == "/api/platform/audit":
                s = _authed(q)
                if not s or s["role"] != "platform":
                    self._json({"ok": False, "error": "无权限"}, 403); return
                ap = _apply_by_id(data.get("applyId"))
                if not ap:
                    self._json({"ok": False, "error": "申请不存在"}); return
                if data.get("pass"):
                    sid = "SH" + secrets.token_hex(3)
                    shop = {"shopId": sid, "shopName": ap["shopName"],
                            "owner": ap["username"], "status": "active",
                            "joinTime": time.strftime("%Y-%m-%d %H:%M:%S")}
                    _cache["shops"].append(shop)
                    _cache["data"][sid] = {}
                    _cache["ac_accounts"].append({"id": "ACC" + secrets.token_hex(3),
                                                  "username": ap["username"], "passwordHash": ap["passwordHash"],
                                                  "role": "supplier", "shopId": sid,
                                                  "name": ap["shopName"], "contact": ap["contact"],
                                                  "phone": ap["phone"], "license": ap["license"],
                                                  "status": "active", "joinTime": shop["joinTime"]})
                    ap["status"] = "pass"; ap["reason"] = ""; ap["shopId"] = sid
                    _audit("audit", s["username"], "通过入驻 " + ap["username"] + " -> " + sid)
                else:
                    ap["status"] = "reject"; ap["reason"] = data.get("reason") or "资料不符合要求"
                    _audit("audit", s["username"], "驳回入驻 " + ap["username"] + "：" + ap["reason"])
                _dirty = True
                self._json({"ok": True, "shopId": ap.get("shopId")})
            elif path == "/api/buy/order":
                s = _authed(q)
                if not s or s["role"] != "buyer":
                    self._json({"ok": False, "error": "无权限"}, 403); return
                sid = data.get("shopId")
                order = data.get("order")
                if not sid or not order:
                    self._json({"ok": False, "error": "参数缺失"}); return
                bucket = _cache["data"].setdefault(sid, {})
                if not order.get("id"):
                    order["id"] = order.get("orderId") or ("BY" + str(int(time.time() * 1000)))
                _ST_CN = {"待处理": "pending", "资质审核": "pending", "正在开单": "pending",
                          "分拣中": "shipping", "待配送": "shipping", "配送中": "shipping",
                          "配送完成": "completed", "已取消": "cancelled", "整单退款": "cancelled"}
                if order.get("status") in _ST_CN:
                    order["status"] = _ST_CN[order["status"]]
                bucket.setdefault("orders", []).insert(0, dict(order, buyer=s.get("username"),
                                                                  buyerShop=s.get("shopId")))
                _dirty = True
                _audit("buy/order", s["username"], order.get("orderId") or order.get("id"))
                self._json({"ok": True, "orderId": order.get("orderId") or order.get("id")})
            elif path == "/api/coupon/claim":
                s = _authed(q)
                if not s or s["role"] != "buyer":
                    self._json({"ok": False, "error": "无权限"}, 403); return
                cid = data.get("couponId") or data.get("id")
                if not cid:
                    self._json({"ok": False, "error": "参数缺失"}); return
                found = False
                for sid, bucket in _cache["data"].items():
                    for c in bucket.get("coupons", []):
                        if c.get("id") == cid or c.get("couponId") == cid:
                            c["claimed"] = int(c.get("claimed") or 0) + 1
                            found = True
                            _dirty = True
                            _audit("coupon/claim", s["username"], cid)
                            break
                    if found:
                        break
                if not found:
                    self._json({"ok": False, "error": "优惠券不存在"}); return
                self._json({"ok": True})
            elif path == "/api/order/status":
                s = _authed(q)
                if not s or s["role"] != "supplier":
                    self._json({"ok": False, "error": "无权限"}, 403); return
                orderId = data.get("orderId") or data.get("id")
                status = data.get("status") or ""
                if not orderId or status not in ("pending", "shipping", "completed", "cancelled"):
                    self._json({"ok": False, "error": "参数错误"}); return
                bucket = _cache["data"].get(s["shopId"], {})
                for o in bucket.get("orders", []):
                    if o.get("orderId") == orderId or o.get("id") == orderId:
                        o["status"] = status
                        _dirty = True
                        _audit("order/status", s["username"], orderId + " -> " + status)
                        self._json({"ok": True, "order": o}); return
                self._json({"ok": False, "error": "订单不存在"})
            elif path == "/api/review":
                s = _authed(q)
                if not s or s["role"] != "buyer":
                    self._json({"ok": False, "error": "无权限"}, 403); return
                orderId = data.get("orderId") or data.get("id")
                rating = int(data.get("rating") or 0)
                if not orderId or rating < 1 or rating > 5:
                    self._json({"ok": False, "error": "参数错误"}); return
                content = (data.get("content") or "").strip()
                target_sid, order = None, None
                for sid, bucket in _cache["data"].items():
                    for o in bucket.get("orders", []):
                        if (o.get("orderId") == orderId or o.get("id") == orderId) and \
                                (o.get("buyerShop") == s["shopId"] or o.get("buyer") == s["username"]):
                            target_sid, order = sid, o
                            break
                    if target_sid:
                        break
                if not target_sid:
                    self._json({"ok": False, "error": "订单不存在"}); return
                shop = _shop_by_id(target_sid)
                bucket = _cache["data"].setdefault(target_sid, {})
                rec = {"id": "RV" + str(int(time.time() * 1000)), "orderId": orderId,
                       "orderTime": order.get("orderTime", ""), "amount": order.get("amount", 0),
                       "rating": rating, "content": content, "buyer": s["username"],
                       "buyerShop": s["shopId"], "shopId": target_sid,
                       "shopName": (shop or {}).get("shopName", ""),
                       "time": time.strftime("%Y-%m-%d %H:%M:%S")}
                bucket.setdefault("reviews", []).insert(0, rec)
                order["reviewed"] = True
                _dirty = True
                _audit("review", s["username"], orderId + " 评分 " + str(rating))
                self._json({"ok": True, "review": rec})
            elif path == "/api/notices/send":
                s = _authed(q)
                if not s or s["role"] != "platform":
                    self._json({"ok": False, "error": "无权限"}, 403); return
                title = (data.get("title") or "").strip()
                content = (data.get("content") or "").strip()
                to = (data.get("to") or "all").strip()
                if not title or not content:
                    self._json({"ok": False, "error": "标题与内容不能为空"}); return
                rec = {"id": "NT" + str(int(time.time() * 1000)), "title": title,
                       "content": content, "from": s["username"], "to": to,
                       "time": time.strftime("%Y-%m-%d %H:%M:%S"), "readBy": []}
                _cache.setdefault("notices", []).insert(0, rec)
                _dirty = True
                _audit("notice/send", s["username"], title + " -> " + to)
                self._json({"ok": True, "notice": rec})
            elif path == "/api/notices/read":
                s = _authed(q)
                if not s:
                    self._json({"ok": False, "error": "未登录"}, 401); return
                nid = data.get("noticeId") or data.get("id")
                for n in _cache.get("notices", []):
                    if n.get("id") == nid and s["username"] not in n.get("readBy", []):
                        n.setdefault("readBy", []).append(s["username"])
                        _dirty = True
                self._json({"ok": True})
            elif path == "/api/settle/submit":
                s = _authed(q)
                if not s or s["role"] != "supplier":
                    self._json({"ok": False, "error": "无权限"}, 403); return
                orderIds = data.get("orderIds") or []
                period = data.get("period") or time.strftime("%Y-%m")
                bucket = _cache["data"].get(s["shopId"], {})
                orders = [o for o in bucket.get("orders", []) if o.get("orderId") in orderIds or o.get("id") in orderIds]
                total = sum(float(o.get("amount") or 0) for o in orders)
                rate = float(_cache["sys_cfg"].get("commissionRate") or 0.05)
                comm = round(total * rate, 2)
                net = round(total - comm, 2)
                rec = {"id": "ST" + str(int(time.time() * 1000)), "shopId": s["shopId"],
                       "period": period, "orderIds": orderIds, "orderCount": len(orders),
                       "totalAmount": total, "commission": comm, "netPay": net,
                       "status": "pending", "submitTime": time.strftime("%Y-%m-%d %H:%M:%S"), "payTime": ""}
                _cache["settles"].insert(0, rec); _dirty = True
                _audit("settle/submit", s["username"], rec["id"] + " 订单数 " + str(len(orders)))
                self._json({"ok": True, "settle": rec})
            elif path == "/api/settle/pay":
                s = _authed(q)
                if not s or s["role"] != "platform":
                    self._json({"ok": False, "error": "无权限"}, 403); return
                for x in _cache["settles"]:
                    if x.get("id") == data.get("settleId"):
                        if x.get("status") == "paid":
                            self._json({"ok": False, "error": "该结算单已打款"}); return
                        x["status"] = "paid"; x["payTime"] = time.strftime("%Y-%m-%d %H:%M:%S"); _dirty = True
                        _audit("settle/pay", s["username"], x["id"] + " 货款 " + str(x.get("netPay")))
                        self._json({"ok": True, "settle": x}); return
                self._json({"ok": False, "error": "结算单不存在"})
            elif path == "/api/platform/cfg":
                s = _authed(q)
                if not s or s["role"] != "platform":
                    self._json({"ok": False, "error": "无权限"}, 403); return
                if "commissionRate" in data:
                    _cache["sys_cfg"]["commissionRate"] = float(data["commissionRate"])
                    _dirty = True
                    _audit("cfg", s["username"], "佣金率 -> " + str(data["commissionRate"]))
                self._json({"ok": True, "cfg": _cache["sys_cfg"]})
            else:
                self._json({"ok": False, "error": "not found"}, 404)

    def do_PUT(self):
        global _dirty
        u = urlparse(self.path)
        path = u.path
        q = parse_qs(u.query)
        data = self._body()
        if data is None:
            self._json({"ok": False, "error": "bad json"}, 400); return
        with _lock:
            if path.startswith("/api/data/") and len(path) > len("/api/data/"):
                col = unquote(path[len("/api/data/"):])
                s = _authed(q)
                if not s or not s.get("shopId"):
                    self._json({"ok": False, "error": "未登录或无店铺"}, 401); return
                arr = data if isinstance(data, list) else data.get("arr", [])
                if not isinstance(arr, list):
                    self._json({"ok": False, "error": "body must be array"}, 400); return
                bucket = _cache["data"].setdefault(s["shopId"], {})
                bucket[col] = arr; _dirty = True
                self._json({"ok": True, "shopId": s["shopId"], "col": col, "count": len(arr)})
            else:
                self._json({"ok": False, "error": "not found"}, 404)

    def log_message(self, fmt, *args):
        pass


def _overview():
    shops = _cache["shops"]
    orders_all, amount_all, comm_all = 0, 0.0, 0.0
    for sid, bucket in _cache["data"].items():
        for o in bucket.get("orders", []):
            orders_all += 1
            amount_all += float(o.get("amount") or 0)
    for st in _cache["settles"]:
        comm_all += float(st.get("commission") or 0)
    return {"shopCount": len(shops),
            "pendingApply": sum(1 for a in _cache["ac_apply"] if a.get("status") == "pending"),
            "buyerCount": sum(1 for a in _cache["ac_accounts"] if a.get("role") == "buyer"),
            "orderCount": orders_all, "tradeAmount": round(amount_all, 2),
            "commissionIncome": round(comm_all, 2),
            "rate": _cache["sys_cfg"].get("commissionRate")}


def _report_overview(sess):
    """汇总卡片：平台=全平台口径，供应商/药店=本店口径"""
    orders = _visible_orders(sess)
    amount = sum(float(o.get("amount") or 0) for o, _, _ in orders)
    buyers = set()
    for o, _, _ in orders:
        if o.get("buyerShop"):
            buyers.add(o.get("buyerShop"))
    sh_ids = set()
    for o, sid, _ in orders:
        sh_ids.add(sid)
    status_cnt = {}
    for o, _, _ in orders:
        st = o.get("status") or "pending"
        status_cnt[st] = status_cnt.get(st, 0) + 1
    rate = float(_cache["sys_cfg"].get("commissionRate") or 0.05)
    comm = round(amount * rate, 2) if sess["role"] == "platform" else 0.0
    return {"orderCount": len(orders), "tradeAmount": round(amount, 2),
            "buyerCount": len(buyers), "shopCount": len(sh_ids),
            "avgOrder": round(amount / len(orders), 2) if orders else 0,
            "commission": comm, "statusCount": status_cnt}


def _report_sales(sess):
    """销售趋势：按订单日期聚合（近 90 天，排除已取消）"""
    agg = {}
    for o, _, _ in _visible_orders(sess):
        if o.get("status") in ("cancelled", "已取消"):
            continue
        day = (o.get("orderTime") or "")[:10]
        if not day:
            continue
        a = agg.setdefault(day, {"date": day, "amount": 0.0, "orders": 0})
        a["amount"] += float(o.get("amount") or 0)
        a["orders"] += 1
    rows = [{"date": k, "amount": round(v["amount"], 2), "orders": v["orders"]}
            for k, v in sorted(agg.items())[-90:]]
    return rows


def _report_products(sess):
    """品种分析：按商品聚合销量/销售额/订单数"""
    agg = {}
    for o, _, _ in _visible_orders(sess):
        if o.get("status") in ("cancelled", "已取消"):
            continue
        for it in o.get("items") or []:
            key = it.get("pid") or it.get("name") or "未知"
            a = agg.setdefault(key, {"pid": it.get("pid"), "name": it.get("name") or key,
                                     "qty": 0, "amount": 0.0, "orders": 0})
            qty = int(it.get("qty") or 1)
            a["qty"] += qty
            a["amount"] += float(it.get("price") or 0) * qty
            a["orders"] += 1
    rows = sorted(agg.values(), key=lambda x: x["amount"], reverse=True)
    for r in rows:
        r["amount"] = round(r["amount"], 2)
    return rows


def _report_traffic(sess):
    """店铺流量：店铺维度订单/买家/销售额/复购率"""
    if sess["role"] == "platform":
        agg = {}
        for o, sid, sname in _visible_orders(sess):
            if o.get("status") in ("cancelled", "已取消"):
                continue
            a = agg.setdefault(sid, {"shopId": sid, "shopName": sname,
                                     "orders": 0, "buyers": set(), "amount": 0.0})
            a["orders"] += 1
            a["buyers"].add(o.get("buyerShop") or o.get("buyer") or "?")
            a["amount"] += float(o.get("amount") or 0)
        rows = []
        for sid, a in agg.items():
            repeat = 0
            for b in a["buyers"]:
                cnt = sum(1 for o, s2, _ in _visible_orders(sess)
                          if s2 == sid and (o.get("buyerShop") or o.get("buyer") or "?") == b)
                if cnt > 1:
                    repeat += 1
            rows.append({"shopId": sid, "shopName": a["shopName"], "orders": a["orders"],
                         "buyerCount": len(a["buyers"]), "amount": round(a["amount"], 2),
                         "repeatBuyers": repeat,
                         "reorderRate": round(repeat / len(a["buyers"]) * 100, 1) if a["buyers"] else 0})
        rows.sort(key=lambda x: x["amount"], reverse=True)
        return rows
    # 供应商/药店：本店订单按买家聚合
    agg = {}
    for o, _, _ in _visible_orders(sess):
        if o.get("status") in ("cancelled", "已取消"):
            continue
        b = o.get("buyerShop") or o.get("buyer") or "?"
        a = agg.setdefault(b, {"orders": 0, "amount": 0.0})
        a["orders"] += 1
        a["amount"] += float(o.get("amount") or 0)
    repeat = sum(1 for a in agg.values() if a["orders"] > 1)
    return [{"orders": sum(a["orders"] for a in agg.values()),
             "buyerCount": len(agg), "amount": round(sum(a["amount"] for a in agg.values()), 2),
             "repeatBuyers": repeat,
             "reorderRate": round(repeat / len(agg) * 100, 1) if agg else 0}]


def _notice_visible(n, sess):
    to = n.get("to") or "all"
    if to == "all" or to == sess["role"] or to == sess.get("shopId") or to == sess["username"]:
        return True
    if to == "supplier" and sess["role"] == "supplier":
        return True
    if to == "buyer" and sess["role"] == "buyer":
        return True
    return False


def main():
    global DATA_FILE, SESSION_TTL, LOCK_MAX, LOCK_SECONDS, BACKUP_INTERVAL, BACKUP_KEEP
    global AUDIT_FILE, ALLOWED_ORIGINS, HOST
    port = DEFAULT_PORT
    data_arg = DATA_FILE
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1]); i += 2
        elif a == "--host" and i + 1 < len(args):
            HOST = args[i + 1]; i += 2
        elif a == "--data" and i + 1 < len(args):
            data_arg = os.path.abspath(args[i + 1]); i += 2
        elif a == "--backup-interval" and i + 1 < len(args):
            BACKUP_INTERVAL = int(args[i + 1]); i += 2
        elif a == "--backup-keep" and i + 1 < len(args):
            BACKUP_KEEP = int(args[i + 1]); i += 2
        elif a == "--audit" and i + 1 < len(args):
            AUDIT_FILE = os.path.abspath(args[i + 1]); i += 2
        elif a == "--allow-origin" and i + 1 < len(args):
            ALLOWED_ORIGINS = [x.strip() for x in args[i + 1].split(",") if x.strip()]
            i += 2
        else:
            i += 1
    DATA_FILE = data_arg
    _load()
    _bg_flush()
    srv = ThreadingHTTPServer((HOST, port), Handler)
    print("[server] 药商帮平台服务 v5 running at http://%s:%d (data: %s)" % (HOST, port, DATA_FILE), flush=True)
    print("[server] audit=%s backups=%s(%ds) session_ttl=%dh lock=%d/%ds allow_origin=%s" % (
        AUDIT_FILE or "off", BACKUP_KEEP, BACKUP_INTERVAL, SESSION_TTL // 3600,
        LOCK_MAX, LOCK_SECONDS, ",".join(ALLOWED_ORIGINS)), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        _save()
        print("[server] stopped")


if __name__ == "__main__":
    main()
