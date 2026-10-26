# -*- coding: utf-8 -*-
#[rule: ^喜马(登录|滑块|验证码|账号|删除)?\s*(.*)$]
#[param: {"required": false, "key": "xmly_login.captcha_port", "remark": "滑块验证页本地端口(默认18089)"}]
#[param: {"required": false, "key": "xmly_login.captcha_addr", "remark": "滑块页对外访问地址(如 http://局域网IP:18089 或 frp 域名)，留空则用 127.0.0.1"}]

'''
喜马拉雅 手机号+短信验证码 登录插件（羽化面板版）
========================================================================
由「喜马拉雅短信登录_风子.exe」(PyInstaller) 还原协议移植：
  1. 面板本地起一个小网页承载极验滑块 -> 在浏览器打开完成滑块 -> fdsOtp 回传
  2. GET  /h5/nonce/{ts}            取签名随机数
  3. POST /h5/sms/forward           发送短信验证码
  4. POST /h5/sms/v2/verify         校验验证码 -> bizKey(smsKey)
  5. POST /h5/login/quick/v2        快速登录 -> Set-Cookie 取 _token
签名：参数按 key 首字母排序拼 k=v&... 再拼 &securityKey，整体大写后 SHA-1。
自动滑块：面板容器内 pip install 'wulu-geetest-bypass[all]' 后，发码前自动过极验滑块（无需浏览器手划）。
手机号：RSA PKCS#1 v1.5 加密（官方公钥）后 Base64。

聊天指令：
  喜马登录          进入交互菜单（1滑块 2发码 3登录保存 4账号列表 5删除账号）
  喜马滑块          直接启动滑块验证页并回复访问地址
  喜马验证码        直接发送短信验证码（未绑滑块 token 会提示先做步骤1）
  喜马账号          查看已绑定账号
  喜马删除          删除账号（按序号）
'''

import base64
import hashlib
import json
import os
import re
import threading
import time
import uuid
import urllib.request
import urllib.parse
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = 'https://passport.ximalaya.com'
SEC_KEY = 'WEB-V1-PRODUCT-E7768904917C4154A925FBE1A3848BC3E84E2C7770744E56AFBC9600C267891F'
CAPTCHA_ID = '4f9ca589ee31bd384760d8d1cec5c675'
UA = 'Mozilla/5.0 (Linux; Android 12; Pixel XL Build/SP1A.210812.015; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version//4.0 Chrome/103.0.0.0 Mobile Safari/537.36'
UA = 'Mozilla/5.0 (Linux; Android 12; Pixel XL Build/SP1A.210812.015; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/103.0.0.0 Mobile Safari/537.36'
REFERER = 'https://m.ximalaya.com/passport/login'
PUB_DER_B64 = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVhaR3Or7suUlwHUl2Ly36uVmboZ3+HhovogDjLgRE9CbaUokS2eqGaVFfbxAUxFThNDuXq/fBD+SdUgppmcZrIw4HMMP4AtE2qJJQH/KxPWmbXH7Lv+9CisNtPYOlvWJ/GHRqf9x3TBKjjeJ2CjuVxlPBDX63+Ecil2JR9klVawIDAQAB'

B_ACC = 'xmly_login_accounts'    # <owner> -> json [{remark, cookie, uid, phone}]
B_OWN = 'xmly_login_owner'       # <uid>   -> owner（账号归属，防多设备顶号风控）
B_STATE = 'xmly_login_state'     # <owner> -> json {phone}
B_TOKEN = 'xmly_login_captcha'   # fds_otp -> json {token, ts}

_SRV = None
_SRV_LOCK = threading.Lock()


def _cfg(key, default=''):
    try:
        v = middleware.bucketGet('xmly_login_config', key)
        return v if v else default
    except Exception:
        return default


def _pub_modulus():
    der = base64.b64decode(PUB_DER_B64)
    i = der.rfind(b'\x02\x81\x81\x00')
    if i < 0:
        raise RuntimeError('公钥解析失败')
    return int.from_bytes(der[i + 4:i + 132], 'big')


PUB_N = _pub_modulus()


def rsa_encrypt(text):
    m = text.encode('utf-8')
    k = 128
    ps_len = k - 3 - len(m)
    ps = bytearray()
    while len(ps) < ps_len:
        b = os.urandom(ps_len - len(ps))
        ps.extend(x for x in b if x != 0)
    blk = b'\x00\x02' + bytes(ps[:ps_len]) + b'\x00' + m
    c = pow(int.from_bytes(blk, 'big'), 65537, PUB_N)
    return base64.b64encode(c.to_bytes(k, 'big')).decode()


def sign_params(d):
    qs = '&'.join(f'{k}={d[k]}' for k in sorted(d, key=lambda k: k))
    return hashlib.sha1((qs + '&' + SEC_KEY).upper().encode()).hexdigest()


def http_json(path, data=None, extra_headers=None, want_headers=False):
    url = path if path.startswith('http') else BASE + path
    headers = {
        'User-Agent': UA,
        'Accept': 'application/json, text/plain, */*',
        'Referer': REFERER,
        'Origin': 'https://m.ximalaya.com',
    }
    body = None
    if data is not None:
        headers['Content-Type'] = 'application/json;charset=UTF-8'
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        raw = resp.read()
        hdrs = resp.headers
    except urllib.error.HTTPError as e:
        raw = e.read()
        hdrs = e.headers
    try:
        j = json.loads(raw.decode('utf-8'))
    except Exception:
        j = {'ret': -999, 'msg': '接口返回非 JSON: ' + raw[:120].decode('utf-8', 'replace')}
    if want_headers:
        return j, hdrs
    return j


def get_nonce():
    j = http_json('/h5/nonce/%d' % int(time.time() * 1000))
    if j.get('ret') != 0:
        raise RuntimeError('获取 nonce 失败: %s' % j.get('msg', j))
    return j['nonce']


def send_sms(mobile_plain, fds_otp):
    enc = rsa_encrypt(mobile_plain)
    nonce = get_nonce()
    params = {'mobile': enc, 'sendType': 1, 'nonce': nonce, 'fdsOtp': fds_otp}
    params['signature'] = sign_params(params)
    j = http_json('/h5/sms/forward', params)
    if j.get('ret') != 0:
        raise RuntimeError(f"ret={j.get('ret')} {j.get('msg', j)}")
    return j.get('msg', '已发送')


def verify_sms(mobile_plain, code):
    enc = rsa_encrypt(mobile_plain)
    nonce = get_nonce()
    params = {'mobile': enc, 'code': code, 'nonce': nonce}
    params['signature'] = sign_params(params)
    j = http_json('/h5/sms/v2/verify', params)
    if j.get('ret') != 0:
        raise RuntimeError(f"验证码校验失败 ret={j.get('ret')} {j.get('msg', j)}")
    return j['bizKey']


def quick_login(mobile_plain, sms_key):
    enc = rsa_encrypt(mobile_plain)
    nonce = get_nonce()
    params = {'mobile': enc, 'smsKey': sms_key, 'nonce': nonce}
    params['signature'] = sign_params(params)
    params['fdsOtp'] = ''
    j, hdrs = http_json('/h5/login/quick/v2', params, want_headers=True)
    if j.get('ret') != 0:
        raise RuntimeError(f"ret={j.get('ret')} {j.get('msg', j)}")
    cookies = []
    for v in (hdrs.get_all('Set-Cookie') or []):
        cookies.append(v.split(';', 1)[0].strip())
    cookie_str = '; '.join(cookies)
    data = j.get('data') or {}
    if '_token=' not in cookie_str:
        for key in ('cookie', 'cookies', 'token'):
            v = data.get(key)
            if isinstance(v, str) and '_token=' in v:
                cookie_str = v
                break
        if isinstance(data, dict):
            for k in ('accessToken', 'token'):
                if k in data and 'uid' in data:
                    cookie_str = f"1&_token={data['uid']}&{data[k]}"
                    break
    uid = ''
    m = re.search(r'_token=(\d+)&', cookie_str)
    if m:
        uid = m.group(1)
    elif isinstance(data, dict) and data.get('uid'):
        uid = str(data['uid'])
    elif True:
        m2 = re.search(r'_token=(\d+)', cookie_str)
        if m2:
            uid = m2.group(1)
    if '_device=' not in cookie_str:
        cookie_str = f"1&_device=android&{uuid.uuid4()}&9.5.13; channel=and-f5; impl=com.ximalaya.ting.android; osversion=29; {cookie_str}"
    return cookie_str, uid, j


CAPTCHA_PAGE = '<!doctype html><html><head><meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1">\n<title>喜马拉雅登录 · 滑块验证</title>\n<style>\nbody{font-family:"Microsoft YaHei",sans-serif;background:#f2f3f5;text-align:center;padding-top:40px}\nh3{color:#1f2329;font-weight:500}\n#jymain{width:300px;margin:30px auto}\n#st{color:#8a8f99;font-size:14px}\n</style></head><body>\n<h3>请拖动完成滑块验证</h3>\n<div id="jymain"></div>\n<p id="st">验证组件加载中…</p>\n<script src="https://s1.xmcdn.com/yx/static-source/last/dist/js/gt4.js"></script>\n<script>\nvar tries=0;\nfunction boot(){\n  if(!window.initGeetest4){\n    if(++tries<10){setTimeout(boot,500);return;}\n    document.getElementById(\'st\').textContent=\'验证组件加载失败，请检查网络后刷新本页\';return;}\n  window.initGeetest4({captchaId:\'%(cid)s\',product:\'bind\',hideSuccess:true},function(c){\n    c.appendTo(\'#jymain\')\n     .onReady(function(){c.showCaptcha();document.getElementById(\'st\').textContent=\'完成滑块后自动继续\';})\n     .onSuccess(function(){\n        var v=c.getValidate();\n        if(!v){return;}\n        document.getElementById(\'st\').textContent=\'验证成功，正在回传…\';\n        fetch(\'/token\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify(v)})\n          .then(function(){document.getElementById(\'st\').textContent=\'完成！请回到机器人继续操作\';})\n          .catch(function(){document.getElementById(\'st\').textContent=\'回传失败，请重新滑动一次\';});\n     })\n     .onError(function(e){document.getElementById(\'st\').textContent=\'验证组件出错，可刷新重试\';});\n  });\n}\nboot();\n</script></body></html>\n' % {'cid': CAPTCHA_ID}


class _CaptchaHandler(BaseHTTPRequestHandler):
    server_version = 'XmlyCaptcha/1.0'

    def log_message(self, *a):
        pass

    def _json(self, d):
        body = json.dumps(d).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith('/token'):
            try:
                cur = json.loads(middleware.bucketGet(B_TOKEN, 'fds_otp') or '{}')
            except Exception:
                cur = {}
            self._json({'got': bool(cur.get('token'))})
            return
        body = CAPTCHA_PAGE.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        mw = globals()['middleware']
        if self.path.startswith('/token'):
            n = int(self.headers.get('Content-Length') or 0)
            raw = self.rfile.read(n)
            try:
                v = json.loads(raw.decode('utf-8'))
                if isinstance(v, dict) and v.get('lot_number'):
                    mw.bucketSet(B_TOKEN, 'fds_otp',
                                         json.dumps({'token': json.dumps(v, ensure_ascii=False),
                                                     'ts': int(time.time())}, ensure_ascii=False))
                self._json({'ok': True})
                return
            except Exception:
                pass
        self.send_response(404)
        self.end_headers()


def ensure_server():
    """启动滑块验证页 HTTP 服务（进程内单例）。返回 (port, 新启动)。"""
    global _SRV
    with _SRV_LOCK:
        if _SRV is not None:
            try:
                if _SRV.server_address and _SRV.server_address[1]:
                    return _SRV.server_address[1], False
            except Exception:
                pass
        port = int(_cfg('captcha_port', '18089') or 18089)
        try:
            srv = ThreadingHTTPServer(('0.0.0.0', port), _CaptchaHandler)
        except OSError:
            srv = ThreadingHTTPServer(('0.0.0.0', 0), _CaptchaHandler)
        _SRV = srv
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv.server_address[1], True


def captcha_url():
    port, _ = ensure_server()
    addr = (_cfg('captcha_addr', '') or '').strip()
    if addr:
        return addr.rstrip('/') + '/'
    return 'http://127.0.0.1:%d/' % port


# ===== 内嵌 icon 求解器（方向图标点选，模型 base64 内嵌）=====

"""icon (方向图标点选) solver bridge for wulu_geetest_bypass.
Adapted from Evil-Bane/Geetest-Solver icon.py (MIT). Solver signature per wulu docs:
solve_icon(imgs: bytes, ques: list[bytes]) -> list[(x,y)] normalized 0~1.
wulu passes imgs/ques as raw image bytes (already downloaded).
"""
import os
import cv2
import numpy as np

try:
    _PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    _PLUGIN_DIR = os.getcwd()
_CACHE_DIR = os.path.join(_PLUGIN_DIR, '_xmly_models')
_ONNX = os.path.join(_CACHE_DIR, 'gw_model.onnx')
_CHARS = os.path.join(_CACHE_DIR, 'gw_charsets.json')


MODEL_URLS = [
    'https://cdn.jsdelivr.net/gh/1160269339/xmly-plugins@main/models/{f}',
    'https://ghproxy.net/https://raw.githubusercontent.com/1160269339/xmly-plugins/main/models/{f}',
    'https://raw.githubusercontent.com/1160269339/xmly-plugins/main/models/{f}',
]


def _dl_model(fname, dest):
    last = None
    for tpl in MODEL_URLS:
        try:
            req = urllib.request.Request(tpl.format(f=urllib.parse.quote(fname)),
                                         headers={'User-Agent': 'Mozilla/5.0'})
            data = urllib.request.urlopen(req, timeout=60).read()
            if len(data) < 100 and b'\x00' not in data[:4] and fname.endswith('.onnx'):
                raise RuntimeError('too small: %d' % len(data))
            with open(dest, 'wb') as fh:
                fh.write(data)
            return True
        except Exception as e:
            last = e
    raise last


def _ensure_models():
    """首次使用时从镜像下载识别模型到缓存目录。"""
    os.makedirs(_CACHE_DIR, exist_ok=True)
    if not os.path.exists(_ONNX):
        _dl_model('gw_model.onnx', _ONNX)
    if not os.path.exists(_CHARS):
        _dl_model('gw_charsets.json', _CHARS)

_det = None
_cnn = None


def _get_det():
    global _det, _cnn
    if _det is None:
        _ensure_models()
        import ddddocr
        _det = ddddocr.DdddOcr(det=True, show_ad=False)
        _cnn = ddddocr.DdddOcr(det=False, ocr=False, show_ad=False,
                               import_onnx_path=_ONNX, charsets_path=_CHARS)
    return _det


def _classify(crop_bytes):
    global _cnn
    _get_det()
    return _cnn.classification(crop_bytes)


def _load_icon(b):
    img = cv2.imdecode(np.frombuffer(b, np.uint8), cv2.IMREAD_UNCHANGED)
    if img is not None and img.ndim == 3 and img.shape[2] == 4:
        alpha = img[:, :, 3] / 255.0
        rgb = img[:, :, :3]
        white = np.ones_like(rgb) * 255
        img = (rgb * alpha[:, :, np.newaxis] + white * (1 - alpha[:, :, np.newaxis])).astype(np.uint8)
    if img is not None and img.ndim == 3:
        img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        img = cv2.bitwise_not(img)  # 黑图标白底 -> 白图标黑底，匹配 crop 极性
    return img


def _match_score(icon, crop):
    try:
        orb = cv2.ORB_create(nfeatures=500, edgeThreshold=5)
        k1, d1 = orb.detectAndCompute(icon, None)
        k2, d2 = orb.detectAndCompute(crop, None)
        if d1 is None or d2 is None or len(d1) < 2 or len(d2) < 2:
            return 0.0
        bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
        matches = sorted(bf.match(d1, d2), key=lambda x: x.distance)
        good = [m for m in matches if m.distance < 64]
        return float(len(good))
    except Exception:
        return 0.0


def solve_icon(imgs, ques) -> list:
    """imgs: captcha 大图 bytes；ques: 问题小图 bytes 列表。返回归一化坐标。"""
    if isinstance(imgs, memoryview):
        imgs = imgs.tobytes()
    ques = [q.tobytes() if isinstance(q, memoryview) else q for q in (ques or [])]
    det = _get_det()
    cap_img = cv2.imdecode(np.frombuffer(imgs, np.uint8), cv2.IMREAD_COLOR)
    h, w = cap_img.shape[:2]
    bboxes = det.detection(imgs)
    gray = cv2.cvtColor(cap_img, cv2.COLOR_BGR2GRAY)
    crops = []
    for bb in bboxes:
        x1, y1, x2, y2 = bb
        pad = 2
        x1, y1 = max(0, x1 - pad), max(0, y1 - pad)
        x2, y2 = min(w, x2 + pad), min(h, y2 + pad)
        crops.append({'box': bb, 'img': gray[y1:y2, x1:x2],
                      'cx': (x1 + x2) / 2, 'cy': (y1 + y2) / 2})
    used = set()
    out = []
    for qb in ques:
        qimg = _load_icon(qb)
        best, bi = -1.0, -1
        for i, c in enumerate(crops):
            if i in used:
                continue
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            enh = clahe.apply(c['img'])
            s = _match_score(qimg, enh)
            if s > best:
                best, bi = s, i
        if bi < 0 or best <= 0:
            remain = [i for i in range(len(crops)) if i not in used]
            if remain:
                bi = remain[0]
            else:
                out.append([0.5, 0.5])
                continue
        used.add(bi)
        c = crops[bi]
        out.append([c['cx'] / w, c['cy'] / h])
    return out


def auto_solve_captcha():
    """本地求解极验4滑块（wulu-geetest-bypass），返回 fdsOtp token 字符串；失败返回 ''。"""
    try:
        import asyncio
        from wulu_geetest_bypass import Geetest
        # 注册 icon(方向图标点选) 求解器：喜马拉雅 adaptive 模式会随机切 icon 题型
        if 'icon' not in Geetest._solvers:
            try:
                Geetest.register_solver('icon', solve_icon)  # 本文件内嵌的求解器
            except Exception:
                pass

        async def _solve():
            last = None
            for attempt in range(3):
                try:
                    g = Geetest(captcha_id=CAPTCHA_ID, risk_type='slide')
                    r = await g.resolve()
                    return json.dumps(r, ensure_ascii=False)
                except NotImplementedError as e:
                    # 极验偶发下发改题型（icon 等），重取一轮
                    last = e
                except Exception as e:
                    last = e
            raise RuntimeError(str(last))

        return asyncio.run(_solve())
    except ImportError:
        return ''
    except Exception as e:
        print('auto_solve_captcha failed:', e)
        return ''


def get_fds_otp():
    try:
        d = json.loads(middleware.bucketGet(B_TOKEN, 'fds_otp') or '{}')
    except Exception:
        return ''
    return d.get('token') or ''


def mask_phone(p):
    return p[:3] + '****' + p[-4:] if len(p) >= 7 else p


def load_accounts(owner):
    try:
        v = middleware.bucketGet(B_ACC, owner)
        acc = json.loads(v) if v else []
    except Exception:
        acc = []
    return acc if isinstance(acc, list) else []


def save_accounts(owner, acc):
    middleware.bucketSet(B_ACC, owner, json.dumps(acc, ensure_ascii=False))


def append_xmly_json(remark, cookie, uid):
    """兼容原工具：尝试把账号追加到插件同目录 xmly_accounts.json（供金币助手共用）。"""
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'xmly_accounts.json')
        accounts = []
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                accounts = json.load(f)
            if not isinstance(accounts, list):
                accounts = []
        for a in accounts:
            if isinstance(a, dict) and uid and a.get('uid') == uid:
                a.update({'remark': remark, 'cookie': cookie})
                break
        else:
            accounts.append({'remark': remark, 'cookie': cookie, 'uid': uid, 'proxy': ''})
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(accounts, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def clean_msg(m):
    return (m or '').strip().replace('\n', '').replace('\r', '').replace(' ', '')


def do_captcha(sender, senderID):
    port, started = ensure_server()
    url = captcha_url()
    sender.reply(
        '🧩 滑块验证页已%s\n%s\n\n请用浏览器打开上面的地址完成滑块，'
        '完成后回来发「喜马验证码」继续。\n(如果浏览器打不开，说明面板机器对你的设备不可达，'
        '请在插件配置里把「滑块页对外访问地址」填成可访问的地址)' % ('启动' if started else '已在运行', url))


def do_send_sms(sender, senderID, phone=None):
    if not phone:
        st = middleware.bucketGet(B_STATE, senderID)
        try:
            st = json.loads(st) if st else {}
        except Exception:
            st = {}
        phone = st.get('phone') or ''
    if not phone:
        sender.reply('请先发手机号（回复「q」取消）：')
        phone = sender.input(60, 1, False)
        if not phone:
            sender.reply('❌ 输入超时')
            exit(0)
        phone = clean_msg(phone)
    if not re.fullmatch(r'1\d{10}', phone):
        sender.reply('❌ 请输入 11 位手机号')
        exit(0)
    otp = get_fds_otp()
    auto_ok = False
    if not otp:
        sender.reply('未检测到滑块 token，正在本地自动过滑块…（约10-30秒）')
        otp = auto_solve_captcha()
        if otp:
            auto_ok = True
            middleware.bucketSet(B_TOKEN, 'fds_otp', json.dumps({'token': otp, 'ts': int(time.time())}))
        else:
            sender.reply('❌ 自动过滑块失败（面板未装 wulu-geetest-bypass 或求解失败）\n请发「喜马滑块」走手动浏览器滑块流程')
            exit(0)
    middleware.bucketSet(B_STATE, senderID, json.dumps({'phone': phone}))
    sender.reply('正在发送验证码到 %s…' % mask_phone(phone))
    try:
        msg = send_sms(phone, otp)
        sender.reply('✅ 发送成功%s: %s\n收到验证码后发「喜马登录」选 3 完成登录' % ('（滑块已自动通过）' if auto_ok else '', msg))
    except Exception as e:
        sender.reply('❌ 发送失败: %s' % e)


def do_login(sender, senderID):
    st = middleware.bucketGet(B_STATE, senderID)
    try:
        st = json.loads(st) if st else {}
    except Exception:
        st = {}
    phone = st.get('phone') or ''
    if not phone:
        sender.reply('请先发手机号（回复「q」取消）：')
        phone = sender.input(60, 1, False)
        if not phone:
            sender.reply('❌ 输入超时')
            exit(0)
        phone = clean_msg(phone)
        if not re.fullmatch(r'1\d{10}', phone):
            sender.reply('❌ 请输入 11 位手机号')
            exit(0)
        middleware.bucketSet(B_STATE, senderID, json.dumps({'phone': phone}))
    code = st.get('code') or ''
    if not code:
        sender.reply('请输入收到的短信验证码（回复「q」取消）：')
        code = sender.input(120, 1, False)
        if not code:
            sender.reply('❌ 输入超时')
            exit(0)
        code = clean_msg(code)
        if not code:
            sender.reply('❌ 验证码不能为空')
            exit(0)
    sender.reply('校验验证码并登录…')
    try:
        biz = verify_sms(phone, code)
        sender.reply('验证码校验通过，正在登录…')
        cookie, uid, resp = quick_login(phone, biz)
        if '_token=' not in cookie:
            raise RuntimeError('登录响应中未找到 _token: ' + json.dumps(resp, ensure_ascii=False)[:200])
        # 账号归属检查：同一 uid 只允许一个机器人用户绑定
        if uid:
            prev = middleware.bucketGet(B_OWN, uid)
            if prev and prev != senderID:
                sender.reply('❌ 该账号已绑定给其他用户，为避免多设备顶号触发风控，已拒绝绑定')
                exit(0)
            middleware.bucketSet(B_OWN, uid, senderID)
        remark = '%s' % mask_phone(phone)
        acc = load_accounts(senderID)
        for a in acc:
            if uid and a.get('uid') == uid:
                a.update({'remark': remark, 'cookie': cookie, 'phone': phone})
                break
        else:
            acc.append({'remark': remark, 'cookie': cookie, 'uid': uid, 'phone': phone})
        save_accounts(senderID, acc)
        file_ok = append_xmly_json(remark, cookie, uid)
        middleware.bucketSet(B_STATE, senderID, json.dumps({'phone': phone}))
        sender.reply('✔ 登录成功！uid=%s 已保存（备注:%s）%s\n发「喜马账号」可查看' %
                     (uid or '未知', remark, '，并已追加 xmly_accounts.json' if file_ok else ''))
    except Exception as e:
        sender.reply('❌ 登录失败: %s' % e)
    exit(0)


def do_list(sender, senderID):
    acc = load_accounts(senderID)
    if not acc:
        sender.reply('暂无绑定账号。发「喜马登录」开始绑定。')
        exit(0)
    lines = ['📋 已绑定账号 %d 个：' % len(acc)]
    for i, a in enumerate(acc, 1):
        lines.append('%d. %s (uid:%s)' % (i, a.get('remark', '?'), a.get('uid') or '未知'))
    lines.append('删除：发「喜马删除 序号」')
    sender.reply('\n'.join(lines))


def do_delete(sender, senderID, arg):
    acc = load_accounts(senderID)
    if not acc:
        sender.reply('暂无绑定账号')
        exit(0)
    if not arg or not arg.isdigit() or not (1 <= int(arg) <= len(acc)):
        sender.reply('用法：喜马删除 序号（1-%d），发「喜马账号」查看列表' % len(acc))
        exit(0)
    idx = int(arg) - 1
    a = acc.pop(idx)
    save_accounts(senderID, acc)
    if a.get('uid'):
        try:
            owner = middleware.bucketGet(B_OWN, a['uid'])
            if owner == senderID:
                middleware.bucketDelete(B_OWN, a['uid'])
        except Exception:
            pass
    sender.reply('🗑 已删除：%s' % a.get('remark', '?'))


def menu_flow(sender, senderID):
    sender.reply('📺 喜马拉雅短信登录\n1. 获取滑块验证\n2. 发送短信验证码\n3. 登录并保存账号\n4. 账号列表\n0. 退出\n请回复序号：')
    c = sender.input(60, 1, False)
    if not c:
        sender.reply('❌ 输入超时')
        exit(0)
    c = clean_msg(c)
    if c == '1':
        do_captcha(sender, senderID)
    elif c == '2':
        do_send_sms(sender, senderID)
    elif c == '3':
        do_login(sender, senderID)
    elif c == '4':
        do_list(sender, senderID)
    elif c == '0':
        sender.reply('已退出')
    else:
        sender.reply('❌ 无效选择')


def main():
    senderID = middleware.getSenderID()
    sender = middleware.Sender(senderID)
    raw = sender.getMessage()
    msg = clean_msg(raw)
    # 提取指令后缀参数（如「喜马验证码 138xxxx」「喜马删除 2」）
    m = re.match(r'^喜马(登录|滑块|验证码|账号|删除)?(.*)$', msg)
    sub = m.group(1) if m else ''
    arg = (m.group(2) or '').strip() if m else ''
    if sub == '滑块':
        do_captcha(sender, senderID)
        exit(0)
    if sub == '验证码':
        do_send_sms(sender, senderID, arg if re.fullmatch(r'1\d{10}', arg) else None)
        exit(0)
    if sub == '账号':
        do_list(sender, senderID)
        exit(0)
    if sub == '删除':
        do_delete(sender, senderID, arg)
        exit(0)
    if arg:
        # 「喜马登录 1234」直接把参数当验证码走登录
        st = middleware.bucketGet(B_STATE, senderID)
        try:
            st = json.loads(st) if st else {}
        except Exception:
            st = {}
        st['code'] = arg
        middleware.bucketSet(B_STATE, senderID, json.dumps(st))
        do_login(sender, senderID)
        exit(0)
    menu_flow(sender, senderID)
    exit(0)


main()
