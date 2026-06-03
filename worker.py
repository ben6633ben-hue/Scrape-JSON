from workers import Response
from js import fetch as js_fetch
import asyncio
import json
import base64
import hmac
import hashlib
import time
from urllib.parse import urlparse, quote_plus, parse_qs
from datetime import datetime, timedelta

SESSION_COOKIE_NAME = "dm_sess"
SESSION_TTL_SEC = 86400
LOGIN_INNER = "login"
TIME_FMT = "%Y-%m-%d %H:%M:%S"

TRUSTPOSITIF_BASE_URL = "https://www.trustpositif.web.id"
RESEND_API_URL = "https://api.resend.com/emails"
CONFIG_ACTIVE_KEY = "active"
CONFIG_BACKUPS_KEY = "backups"

DEFAULT_CONFIG = {"active": {}, "backups": []}

MAX_CONFIG_BODY_BYTES = 256 * 1024
MAX_ACTIVE_SLOTS = 50
MAX_BACKUPS = 100
MAX_DOMAIN_LEN = 253
MAX_SLOT_LEN = 64
RESEND_API_KEY = None
RESEND_FROM_EMAIL = None
RESEND_TO_EMAIL = None


def _get_secret_path(env):
    """SECRET_PATH from env (alphanumeric) or None. Hides UI/API under /{secret}/."""
    v = _env_str(env, "SECRET_PATH")
    if not v or not v.strip():
        return None
    v = v.strip().strip("/")
    return v if v and all(c.isalnum() for c in v) else None


_PATH_ROUTES = {
    "/": "__ui__", "/index.html": "__ui__",
    "/api/config": "config", "/api/status": "status",
    "/api/active": "active", "/api/backups": "backups", "/api/backup": "backups",
    "/api/run": "run", "/check": "run",
    "/api/test-email": "test-email", "/login": LOGIN_INNER, "/api/login": LOGIN_INNER,
}
# Public endpoints: always at root, no SECRET_PATH or auth
_PATH_PUBLIC = {"/active": "active", "/backups": "backups", "/backup": "backups", "/config": "config"}


def _path_resolve(path, secret):
    """(base_path, inner_key) or (None, None) if path not under secret."""
    path = (path or "").strip().rstrip("/") or "/"
    if path in _PATH_PUBLIC:
        return "", _PATH_PUBLIC[path]
    if secret:
        prefix = "/" + secret
        if path != prefix and not path.startswith(prefix + "/"):
            return None, None
        inner_raw = (path[len(prefix):] or "").strip("/")
        inner = _PATH_ROUTES.get("/" + inner_raw) if inner_raw else "__ui__"
        if inner is None:
            inner = inner_raw or "__ui__"
        return prefix, inner
    inner = _PATH_ROUTES.get(path)
    if inner is not None:
        return "", inner
    if "/test-api" in path:
        return "", "test-api"
    if "/test" in path:
        return "", "test"
    return "", None


def _get_auth_credentials(env):
    """(admin_user, admin_password, session_secret) from env, or None if auth not configured."""
    user = _env_str(env, "ADMIN_USER")
    password = _env_str(env, "ADMIN_PASSWORD")
    secret = _env_str(env, "ADMIN_SESSION_SECRET")
    if not password or not isinstance(password, str):
        return None
    user = (user or "admin").strip() if user else "admin"
    if not secret or not isinstance(secret, str):
        secret = hashlib.sha256((password + ":session_salt").encode()).hexdigest()
    return (user, password, secret.strip())


def _verify_password(provided_user: str, provided_password: str, creds) -> bool:
    if not creds:
        return False
    admin_user, admin_password, _ = creds
    if not provided_user or not provided_password:
        return False
    ok_user = hmac.compare_digest(provided_user.strip().encode("utf-8"), admin_user.encode("utf-8"))
    ok_pass = hmac.compare_digest(provided_password.encode("utf-8"), admin_password.encode("utf-8"))
    return ok_user and ok_pass


def _make_session_cookie(user: str, base_path: str, session_secret: str) -> str:
    """Signed session cookie (payload.sig)."""
    expiry = int(time.time()) + SESSION_TTL_SEC
    payload = base64.urlsafe_b64encode(("%s:%d" % (user, expiry)).encode()).decode().rstrip("=")
    sig = hmac.new(session_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return "%s.%s" % (payload, sig)


def _verify_session_cookie(cookie_val: str, session_secret: str) -> bool:
    """True if signature valid and not expired."""
    if not cookie_val or "." not in cookie_val:
        return False
    payload, sig = cookie_val.rsplit(".", 1)
    try:
        raw = base64.urlsafe_b64decode(payload + "==")
        parts = raw.decode().split(":")
        if len(parts) != 2:
            return False
        expiry = int(parts[1])
        if expiry < int(time.time()):
            return False
        expected = hmac.new(session_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


def _get_cookie(request, name: str) -> str:
    """Cookie value by name from request."""
    try:
        h = request.headers.get("Cookie") or request.headers.get("cookie") or ""
        if not h:
            return ""
        for part in h.split(";"):
            part = part.strip()
            if part.startswith(name + "="):
                return part[len(name) + 1:].strip().strip('"')
    except Exception:
        pass
    return ""


def _get_basic_auth(request) -> tuple:
    """(username, password) from Basic auth or ("", "")."""
    try:
        auth = request.headers.get("Authorization") or request.headers.get("authorization") or ""
        if not auth.startswith("Basic "):
            return ("", "")
        b = base64.b64decode(auth[6:].strip())
        decoded = b.decode("utf-8", "replace")
        if ":" in decoded:
            u, p = decoded.split(":", 1)
            return (u, p)
    except Exception:
        pass
    return ("", "")


def _is_authenticated(request, base_path: str, creds) -> bool:
    """True if session cookie or Basic auth valid."""
    if not creds:
        return True
    _, _, session_secret = creds
    cookie = _get_cookie(request, SESSION_COOKIE_NAME)
    if cookie and _verify_session_cookie(cookie, session_secret):
        return True
    user, password = _get_basic_auth(request)
    if user and password and _verify_password(user, password, creds):
        return True
    return False


def _cors_headers():
    """CORS headers for read-only public endpoints (GET /active, /backups, /config only)."""
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET",
        "Access-Control-Max-Age": "86400",
    }


def _json_headers():
    """Headers for JSON API responses (no CORS)."""
    return {"Content-Type": "application/json"}


def _json_headers_read_only():
    """Headers for public read-only JSON (active, backups, config GET) — includes CORS."""
    return {"Content-Type": "application/json", **_cors_headers()}


def _security_headers():
    """Security headers for all responses (no CORS)."""
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    }


def get_login_html(base_path: str, error: str = ""):
    """Login page HTML (admin only, no sign-up)."""
    action = (base_path or "") + "/" + LOGIN_INNER
    if not action.startswith("/"):
        action = "/" + action
    err = ('<p class="login-error">Invalid username or password.</p>' if error else "")
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Login</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #0f0f12; color: #e4e4e7; }
    .login-box { background: #18181b; border: 1px solid #27272a; border-radius: 8px; padding: 1.5rem; width: 100%; max-width: 320px; }
    h1 { font-size: 1.1rem; margin: 0 0 1rem 0; font-weight: 600; }
    label { display: block; font-size: 0.85rem; color: #a1a1aa; margin-bottom: 0.25rem; }
    input { width: 100%; padding: 0.5rem 0.6rem; margin-bottom: 0.75rem; border: 1px solid #3f3f46; border-radius: 6px; background: #0f0f12; color: #e4e4e7; font-size: 1rem; }
    button { width: 100%; padding: 0.6rem; border: none; border-radius: 6px; background: #3b82f6; color: #fff; font-size: 0.95rem; cursor: pointer; }
    button:hover { background: #2563eb; }
    input:focus-visible, button:focus-visible { outline: 2px solid #3b82f6; outline-offset: 2px; }
    .login-error { color: #fca5a5; font-size: 0.875rem; margin-bottom: 0.75rem; }
  </style>
</head>
<body>
  <div class="login-box">
    <h1>Admin Login</h1>
    """ + err + """
    <form method="post" action=""" + json.dumps(action) + """>
      <label for="user">Username</label>
      <input type="text" id="user" name="user" required autocomplete="username">
      <label for="pass">Password</label>
      <input type="password" id="pass" name="pass" required autocomplete="current-password">
      <button type="submit">Log in</button>
    </form>
  </div>
</body>
</html>"""


def _backups_check_factor(active_count: int) -> float:
    """Backups to check = active_count * factor; factor decreases as active grows."""
    if active_count <= 0:
        return 0.0
    if active_count == 1:
        return 2.0
    if active_count <= 3:
        return 1.5
    if active_count <= 6:
        return 1.0
    if active_count <= 10:
        return 0.75
    return 0.5


def _env_str(env, key: str, default=None):
    """Get string from env, unwrapping JsProxy if needed."""
    v = getattr(env, key, default)
    if v is not None and is_jsproxy(v):
        v = str(js_to_py(v))
    return v if (v is None or isinstance(v, str)) else str(v)


def _in_quiet_hours(env) -> bool:
    """True if current time (local) is in quiet hours or maintenance window — cron should skip. Uses TZ_OFFSET_HOURS; QUIET_START_HOUR/QUIET_END_HOUR (e.g. 23, 6); QUIET_MAINTENANCE_DAY/START/END (e.g. 3, 6, 9 for Thu 6am–9am)."""
    try:
        offset_s = _env_str(env, "TZ_OFFSET_HOURS", "0")
        offset = int(offset_s.strip()) if offset_s else 0
    except (ValueError, TypeError):
        offset = 0
    utc_now = datetime.utcnow()
    local_dt = utc_now + timedelta(hours=offset)

    start_s = _env_str(env, "QUIET_START_HOUR")
    end_s = _env_str(env, "QUIET_END_HOUR")
    if start_s and end_s:
        try:
            start_h = int(start_s.strip())
            end_h = int(end_s.strip())
            if start_h > end_h:
                if local_dt.hour >= start_h or local_dt.hour < end_h:
                    return True
            elif start_h <= local_dt.hour < end_h:
                return True
        except (ValueError, TypeError):
            pass

    day_s = _env_str(env, "QUIET_MAINTENANCE_DAY")
    m_start_s = _env_str(env, "QUIET_MAINTENANCE_START_HOUR")
    m_end_s = _env_str(env, "QUIET_MAINTENANCE_END_HOUR")
    if day_s and m_start_s and m_end_s:
        try:
            # weekday(): Monday=0, Thursday=3, Sunday=6
            if local_dt.weekday() == int(day_s.strip()):
                m_start = int(m_start_s.strip())
                m_end = int(m_end_s.strip())
                if m_start <= local_dt.hour < m_end:
                    return True
        except (ValueError, TypeError):
            pass
    return False


def normalize_domain(domain) -> str:
    """Host only, no scheme/www/port/path; '' if invalid. Max length MAX_DOMAIN_LEN."""
    if domain is None:
        return ""
    domain = str(domain).strip()
    domain = " ".join(domain.split())
    if not domain:
        return ""
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        domain = (parsed.netloc or parsed.path or "").strip()
    if "/" in domain:
        domain = domain.split("/")[0].strip()
    if ":" in domain:
        parts = domain.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            domain = parts[0].strip()
    if domain.startswith("www."):
        domain = domain[4:].lstrip(".")
    domain = domain.rstrip("/").strip()
    if not domain or domain in (".", ".."):
        return ""
    if len(domain) > MAX_DOMAIN_LEN:
        domain = domain[:MAX_DOMAIN_LEN]
    return domain


def sanitize_slot(slot) -> str:
    """Safe slot key: alphanumeric, _-; max length MAX_SLOT_LEN; '' if invalid."""
    if slot is None:
        return ""
    s = str(slot).strip()
    if not s:
        return ""
    s = "".join(c for c in s if c.isalnum() or c in "_-")[:MAX_SLOT_LEN]
    return s


def _normalize_backups(backups):
    """Dedupe by host, drop invalid; capped at MAX_BACKUPS."""
    if not isinstance(backups, list):
        return []
    seen = set()
    out = []
    for d in backups:
        if d is None:
            continue
        s = str(d).strip()
        if not s:
            continue
        n = normalize_domain(s)
        if not n or n in seen:
            continue
        seen.add(n)
        out.append(s)
        if len(out) >= MAX_BACKUPS:
            break
    return out


def _domain_to_url(domain: str):
    """HTTPS URL for domain, or None if invalid/empty."""
    d = normalize_domain(domain) if domain else ""
    return ("https://" + d) if d else None


def _unique_urls_by_host(url_list):
    """One URL per normalized host (first seen wins). Order preserved."""
    seen = set()
    out = []
    for u in url_list:
        if not u:
            continue
        h = normalize_domain(u)
        if h and h not in seen:
            seen.add(h)
            out.append(u)
    return out


def is_jsproxy(obj):
    """True if obj is a JsProxy (Python Workers bridge)."""
    try:
        type_name = type(obj).__name__
        if "JsProxy" in type_name or "Proxy" in type_name:
            return True
        if hasattr(obj, "to_py") or (hasattr(obj, "__class__") and "js" in str(obj.__class__).lower()):
            return True
    except Exception:
        pass
    return False


def js_to_py(obj):
    """JsProxy → native Python dict/list/str."""
    if obj is None:
        return None
    
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    
    try:
        if hasattr(obj, "to_py"):
            return js_to_py(obj.to_py())
    except Exception:
        pass
    
    if is_jsproxy(obj):
        try:
            if hasattr(obj, 'keys') or hasattr(obj, '__getitem__'):
                from js import Object
                try:
                    keys = Object.keys(obj)
                    if keys and hasattr(keys, 'length'):
                        result = {}
                        for i in range(int(keys.length)):
                            key = keys[i]
                            result[str(key)] = js_to_py(obj[key])
                        if result:
                            return result
                except Exception:
                    try:
                        result = {}
                        for key in obj:
                            result[str(key)] = js_to_py(obj[key])
                        if result:
                            return result
                    except Exception:
                        pass
        except Exception:
            pass

    try:
        if hasattr(obj, "__iter__") and not isinstance(obj, (str, bytes)):
            if hasattr(obj, 'length') or hasattr(obj, '__len__'):
                length = obj.length if hasattr(obj, 'length') else len(obj)
                return [js_to_py(obj[i]) for i in range(length)]
            return [js_to_py(item) for item in obj]
    except Exception:
        pass
    
    if isinstance(obj, dict):
        return {str(k): js_to_py(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [js_to_py(item) for item in obj]
    
    try:
        return str(obj)
    except Exception:
        return None


def ensure_json_serializable(obj):
    """Deep-convert to JSON-serializable types."""
    if obj is None:
        return None
    
    if is_jsproxy(obj):
        obj = js_to_py(obj)
    
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    
    if isinstance(obj, dict):
        return {str(k): ensure_json_serializable(v) for k, v in obj.items()}
    
    if isinstance(obj, (list, tuple)):
        return [ensure_json_serializable(item) for item in obj]
    
    try:
        return str(obj)
    except Exception:
        return None


def safe_json_dumps(obj, **kwargs):
    """JSON dumps with JsProxy-safe default."""
    cleaned_obj = ensure_json_serializable(obj)
    
    def default_handler(obj):
        if is_jsproxy(obj):
            return ensure_json_serializable(js_to_py(obj))
        try:
            return str(obj)
        except Exception:
            return None
    
    if 'default' not in kwargs:
        kwargs['default'] = default_handler
    
    return json.dumps(cleaned_obj, **kwargs)


async def to_python_text(response_text_js):
    """Response body (JsProxy or str) → Python str."""
    if not is_jsproxy(response_text_js):
        return str(response_text_js)
    
    if hasattr(response_text_js, 'to_py'):
        return str(response_text_js.to_py())
    
    return str(response_text_js)


def _get_kv(env):
    return getattr(env, "DOMAIN_CONFIG", None)


def _normalize_active(active):
    """active list/dict → {slot: url}; invalid/deduped; max MAX_ACTIVE_SLOTS applied in put_config."""
    out = {}
    if isinstance(active, list):
        for i, d in enumerate(active):
            if d is None:
                continue
            v = str(d).strip()
            if not v:
                continue
            norm = normalize_domain(v)
            if not norm:
                continue
            slot = sanitize_slot(str(i + 1)) or str(i + 1)
            if slot:
                out[slot] = v
    elif isinstance(active, dict):
        for k, v in active.items():
            if k is None:
                continue
            slot = sanitize_slot(k)
            if not slot:
                continue
            if v is None:
                continue
            v = str(v).strip()
            if not v:
                continue
            norm = normalize_domain(v)
            if not norm:
                continue
            out[slot] = v
    return out


async def get_config(env):
    """Load config from KV. active and backups stored in separate keys. Returns {active: {slot: url}, backups: [url, ...]}."""
    kv = _get_kv(env)
    if not kv:
        return dict(DEFAULT_CONFIG)
    try:
        active_raw = await kv.get(CONFIG_ACTIVE_KEY)
        backups_raw = await kv.get(CONFIG_BACKUPS_KEY)
        active = {}
        if active_raw is not None:
            raw = active_raw if isinstance(active_raw, str) else (getattr(active_raw, "to_py", lambda: active_raw) and str(active_raw))
            data = json.loads(raw)
            data = js_to_py(data) if is_jsproxy(data) else data
            if isinstance(data, dict):
                active = _normalize_active(data)
            else:
                active = _normalize_active(data) if isinstance(data, list) else {}
        backups = []
        if backups_raw is not None:
            raw = backups_raw if isinstance(backups_raw, str) else (getattr(backups_raw, "to_py", lambda: backups_raw) and str(backups_raw))
            data = json.loads(raw)
            data = js_to_py(data) if is_jsproxy(data) else data
            backups = _normalize_backups(data if isinstance(data, list) else [])
        return {"active": active, "backups": backups}
    except Exception:
        return dict(DEFAULT_CONFIG)


async def put_config(env, config):
    """Persist config. active and backups written to separate KV keys. active stored as plain JSON object e.g. {\"FB\": \"https://...\", ...}."""
    kv = _get_kv(env)
    if not kv:
        print("[config] KV binding missing; config not persisted")
        return False
    active = _normalize_active(config.get("active"))
    if len(active) > MAX_ACTIVE_SLOTS:
        keys = list(active.keys())[:MAX_ACTIVE_SLOTS]
        active = {k: active[k] for k in keys}
    backups = _normalize_backups(config.get("backups") or [])
    await kv.put(CONFIG_ACTIVE_KEY, json.dumps(active))
    await kv.put(CONFIG_BACKUPS_KEY, json.dumps(backups))
    print("[config] saved active_slots=%d backups=%d" % (len(active), len(backups)))
    return True


async def fetch_domain_status(domain: str):
    """GET domain; returns (normalized_domain, status_code). Consumes body."""
    norm = normalize_domain(domain)
    if not norm:
        return ("", 0)
    url = _domain_to_url(domain)
    if not url:
        return ("", 0)
    try:
        response = await js_fetch(url, method="GET")
        status_code = int(response.status) if hasattr(response, "status") else 0
        try:
            await response.text()
        except Exception:
            pass
        return (norm, status_code)
    except Exception:
        return (norm, 0)


async def is_domain_healthy(domain: str):
    """(healthy, status_code, is_blocked). Healthy = 200 and not blocked."""
    norm = normalize_domain(domain)
    if not norm:
        return False, 0, False
    url = _domain_to_url(domain)
    if not url:
        return False, 0, False
    status_code = 0
    try:
        response = await js_fetch(url, method="GET")
        status_code = int(response.status) if hasattr(response, "status") else 0
        status_ok = status_code == 200
        try:
            await response.text()
        except Exception:
            pass
    except Exception:
        status_ok = False
    is_blocked, _ = await check_domain_blocked(norm)
    healthy = status_ok and not is_blocked
    return healthy, status_code, is_blocked


async def _check_domain_blocked_single(domain: str):
    """One domain → (domain, is_blocked, info). Fallback when batch API fails."""
    is_blocked, info = await check_domain_blocked(domain)
    return (domain, is_blocked, info)


async def check_domains_blocked_batch(domains: list):
    """Batch block check; one API call or parallel singles. Returns {domain: (is_blocked, info)}."""
    domains = [n for d in domains if d for n in [normalize_domain(d)] if n]
    if not domains:
        return {}
    unique = list(dict.fromkeys(domains))
    if len(unique) == 1:
        d = unique[0]
        is_blocked, info = await check_domain_blocked(d)
        return {d: (is_blocked, info)}
    try:
        domains_param = ",".join(unique)
        api_url = f"{TRUSTPOSITIF_BASE_URL}/api/check-kominfo?domains={quote_plus(domains_param)}"
        response = await js_fetch(api_url, method="GET")
        response_text_js = await response.text()
        response_text = await to_python_text(response_text_js)
        if not response.ok:
            raise Exception("batch API not ok")
        api_data = json.loads(response_text)
        api_data = js_to_py(api_data) if is_jsproxy(api_data) else api_data
        if isinstance(api_data, dict) and "error" in api_data:
            raise Exception(api_data.get("error", "API error"))
        out = {}
        for d in unique:
            is_blocked, status_found = _extract_blocked_status(api_data, d)
            out[d] = (is_blocked, {"domain": d, "is_blocked": is_blocked, "status_found": status_found})
        return out
    except Exception:
        results = await asyncio.gather(
            *[_check_domain_blocked_single(d) for d in unique],
            return_exceptions=True
        )
        out = {}
        for r in results:
            if isinstance(r, Exception):
                continue
            domain, is_blocked, info = r
            out[domain] = (is_blocked, info)
        return out


async def check_domain_blocked(domain: str):
    """Trustpositif API: (is_blocked, info)."""
    try:
        search_domain = normalize_domain(domain)
        if not search_domain:
            return False, {"domain": "", "error": "Invalid or empty domain", "is_blocked": False}
        api_url = f"{TRUSTPOSITIF_BASE_URL}/api/check-kominfo?domains={quote_plus(search_domain)}"
        
        response = await js_fetch(api_url, method="GET")
        
        response_text_js = await response.text()
        response_text = await to_python_text(response_text_js)
        
        if not response.ok:
            raise Exception(f"API returned HTTP {response.status}: {response_text}")
        
        try:
            api_data = json.loads(response_text)
            api_data = js_to_py(api_data) if is_jsproxy(api_data) else api_data
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse API response as JSON: {e}, response: {response_text[:200]}")
        
        if isinstance(api_data, dict) and "error" in api_data:
            raise Exception(f"API error: {api_data['error']}")
        
        is_blocked, status_found = _extract_blocked_status(api_data, search_domain)
        
        if not status_found:
            return False, {
                "domain": search_domain,
                "is_blocked": False,
                "status_found": False,
                "error": "Domain not found in API response",
                "api_response": api_data
            }
        
        return is_blocked, {
            "domain": search_domain,
            "is_blocked": is_blocked,
            "status_found": True,
            "api_response": api_data
        }
        
    except Exception as e:
        import traceback
        print(f"ERROR checking domain {domain}: {e}")
        print(f"ERROR traceback: {traceback.format_exc()}")
        return False, {"error": str(e), "error_type": type(e).__name__, "domain": domain}


def _extract_blocked_status(api_data: dict, search_domain: str):
    """(is_blocked, found) from Trustpositif response."""
    if search_domain in api_data:
        domain_data = api_data[search_domain]
        if isinstance(domain_data, dict):
            return bool(domain_data.get("blocked", False)), True
    
    for domain_var in [f"https://{search_domain}", f"http://{search_domain}"]:
        if domain_var in api_data:
            domain_data = api_data[domain_var]
            if isinstance(domain_data, dict):
                return bool(domain_data.get("blocked", False)), True
    
    search_domain_lower = search_domain.lower()
    for key, value in api_data.items():
        if isinstance(key, str) and isinstance(value, dict):
            if search_domain_lower in key.lower():
                return bool(value.get("blocked", False)), True
    
    return False, False


def _get_email_config(env):
    return (
        _env_str(env, "RESEND_API_KEY") or RESEND_API_KEY,
        _env_str(env, "RESEND_FROM_EMAIL") or RESEND_FROM_EMAIL,
        _env_str(env, "RESEND_TO_EMAIL") or RESEND_TO_EMAIL,
    )


async def send_email(env, subject: str, body: str):
    api_key, from_email, to_email = _get_email_config(env)
    if not api_key or not from_email or not to_email:
        print("[email] config missing; skipping send")
        return False
    api_key = str(api_key)
    from_email = str(from_email)
    to_email = str(to_email)
    try:
        email_payload = {"from": from_email, "to": [to_email], "subject": str(subject), "text": str(body)}
        body_str = json.dumps(email_payload)
        response = await js_fetch(
            RESEND_API_URL,
            method="POST",
            headers=[
                ("Authorization", f"Bearer {api_key}"),
                ("Content-Type", "application/json"),
            ],
            body=body_str,
        )
        if response.ok:
            try:
                await response.text()
            except Exception:
                pass
            print("[email] sent subject=%s" % (subject[:50],))
            return True
        error_text = await to_python_text(await response.text())
        print("[email] failed HTTP %s %s" % (response.status, error_text[:100]))
        return False
    except Exception as e:
        print("[email] error: %s" % (e,))
        return False


async def run_failover(env):
    config = await get_config(env)
    active = dict(config["active"])
    backups = list(config["backups"])
    slots_ordered = list(active.keys())
    changes = []
    emails_sent = []

    api_key, _, _ = _get_email_config(env)
    print("[failover] start active_slots=%d backups=%d email_configured=%s" % (len(active), len(backups), bool(api_key)))

    active_count = len(active)
    factor = _backups_check_factor(active_count)
    max_backups_to_check = max(1, min(len(backups), int(active_count * factor))) if active_count else 0
    backups_to_check = list(backups)[:max_backups_to_check]
    all_domains = [n for d in list(active.values()) + backups_to_check if d for n in [normalize_domain(d)] if n]
    all_domains = list(dict.fromkeys(all_domains))
    print("[failover] blocked check for %d domains (active=%d, backups_checked=%d, factor=%.2f)" % (len(all_domains), active_count, len(backups_to_check), factor))
    blocked_map = await check_domains_blocked_batch(all_domains)

    def _is_blocked(domain):
        return blocked_map.get(domain, (False,))[0]

    def _healthy(domain):
        return not _is_blocked(domain)

    initial_backup_count = len(backups)
    blocked_backups = [b for b in backups_to_check if _is_blocked(normalize_domain(b))]
    if blocked_backups:
        backups = [x for x in backups if x not in blocked_backups]
        await put_config(env, {"active": active, "backups": backups})
        for b in blocked_backups:
            print("[failover] backup removed (blocked): %s" % (b,))
        print("[failover] sites removed (blocked): %s" % ", ".join(normalize_domain(b) or b for b in blocked_backups))

    if initial_backup_count > 0 and len(backups) <= 1:
        if len(backups) == 0:
            body = (
                "All of your backup links were removed because they are blocked.\n\n"
                "You have no backup links left. Please add new backup links in your link monitor so we can switch to them if a main link goes down.\n\n"
                "Checked at: " + datetime.now().strftime(TIME_FMT)
            )
            subject = "No backup links left"
        else:
            body = (
                "Some of your backup links were blocked and removed. Only one backup link is left.\n\n"
                "Remaining backup link:\n  • %s\n\n"
                "We recommend adding more backup links so you have a safety net if this one has issues.\n\n"
                "Checked at: %s" % (backups[0], datetime.now().strftime(TIME_FMT))
            )
            subject = "Only one backup link left"
        ok = await send_email(env, subject, body)
        if ok:
            emails_sent.append("backup_count_low")
            print("[failover] email sent: backup count low (%d left)" % len(backups))

    backups_set = set(backups)
    for slot_label in slots_ordered:
        domain = active.get(slot_label)
        if not domain:
            continue
        d = normalize_domain(domain)
        if _healthy(d):
            continue

        promoted_backup = None
        for backup in list(backups_to_check):
            if backup not in backups_set:
                continue
            b = normalize_domain(backup)
            if _is_blocked(b):
                backups = [x for x in backups if x != backup]
                backups_set = set(backups)
                await put_config(env, {"active": active, "backups": backups})
                print("[failover] backup removed (blocked): %s" % (backup,))
                continue
            promoted_backup = backup
            break

        if promoted_backup:
            active[slot_label] = promoted_backup
            backups = [x for x in backups if x != promoted_backup]
            backups_set = set(backups)
            await put_config(env, {"active": active, "backups": backups})
            changes.append({
                "slot": slot_label,
                "replaced": domain,
                "with_backup": promoted_backup
            })
            print("[failover] slot %s blocked: %s -> promoted backup %s" % (slot_label, domain, promoted_backup))
            print("[failover] site removed from backups (promoted): %s" % (normalize_domain(promoted_backup) or promoted_backup))
            continue

        other_slots = [s for s in slots_ordered if s != slot_label and active.get(s)]
        other_actives = [active[s] for s in other_slots if active.get(s)]
        current_norm = normalize_domain(domain)
        other_different = [url for url in other_actives if normalize_domain(url) != current_norm]
        if other_different:
            fallback = other_different[0]
            active[slot_label] = fallback
            await put_config(env, {"active": active, "backups": backups})
            changes.append({"slot": slot_label, "replaced": domain, "with_other_active": fallback})
            print("[failover] slot %s blocked: %s -> other active %s (no backup)" % (slot_label, domain, fallback))
            continue

    down_slots = []
    for slot_label in slots_ordered:
        domain = active.get(slot_label)
        if not domain:
            continue
        d = normalize_domain(domain)
        is_blocked = _is_blocked(d)
        if is_blocked:
            down_slots.append((slot_label, domain, 0, is_blocked))

    down_domains = _unique_urls_by_host([d for _, d, _, _ in down_slots])
    if down_domains:
        body_lines = [
            "The following links are not working and no backup could be used." if len(down_domains) > 1 else "A link is not working and no backup could be used.",
            "",
            "Link(s) that are down:",
            ""
        ]
        body_lines.extend("  • " + d for d in down_domains)
        body_lines.extend([
            "",
            "What you can do:",
            "  • Add or fix backup links in your link monitor.",
            "  • Check why these links are not responding.",
            "",
            "Checked at: " + datetime.now().strftime(TIME_FMT),
        ])
        subject = "All your main links are down" if len(down_domains) > 1 and not backups else "Links are down"
        ok = await send_email(env, subject, "\n".join(body_lines))
        if ok:
            emails_sent.append("links_down")
            print("[failover] email sent: links down (combined)")

    # After promotions we may have 0 or 1 backup left; alert if we didn't already this run
    if len(backups) <= 1 and "backup_count_low" not in emails_sent:
        if len(backups) == 0:
            body = (
                "You have no backup links left (one was used to replace a main link, or they were removed).\n\n"
                "Please add new backup links in your link monitor so we can switch to them if a main link goes down.\n\n"
                "Checked at: " + datetime.now().strftime(TIME_FMT)
            )
            subject = "No backup links left"
        else:
            body = (
                "Only one backup link is left (one was used to replace a main link, or others were removed).\n\n"
                "Remaining backup link:\n  • %s\n\n"
                "We recommend adding more backup links so you have a safety net if this one has issues.\n\n"
                "Checked at: %s" % (backups[0], datetime.now().strftime(TIME_FMT))
            )
            subject = "Only one backup link left"
        ok = await send_email(env, subject, body)
        if ok:
            emails_sent.append("backup_count_low")
            print("[failover] email sent: backup count low (%d left)" % len(backups))

    print("[failover] done changes=%d down_slots=%d emails_sent=%d" % (len(changes), len(down_slots), len(emails_sent)))
    return {
        "active": active,
        "backups": backups,
        "changes": changes,
        "down_slots": [{"slot": s, "domain": d, "status_code": sc, "blocked": bl} for s, d, sc, bl in down_slots],
        "emails_sent": emails_sent
    }


async def on_scheduled(event, env, ctx):
    print("[failover] cron triggered at %s" % (datetime.now().isoformat(),))
    if _in_quiet_hours(env):
        print("[failover] skipped (quiet hours)")
        return
    try:
        result = await run_failover(env)
        if result["changes"]:
            print("[failover] applied: %s" % (result["changes"],))
        if result["down_slots"]:
            print("[failover] down_slots: %s" % (result["down_slots"],))
        if result["emails_sent"]:
            print("[failover] emails_sent: %s" % (result["emails_sent"],))
    except Exception as e:
        print("[failover] error: %s" % (e,))
        import traceback
        tb = traceback.format_exc()
        body = (
            "The automatic link check did not run or encountered an error.\n\n"
            "Error: %s\n\n"
            "Technical details (for support):\n%s\n\n"
            "Time: %s" % (e, tb, datetime.now().strftime(TIME_FMT))
        )
        try:
            ok = await send_email(env, "Link monitor: automatic check failed", body)
            if ok:
                print("[failover] email sent: service error")
        except Exception as email_err:
            print("[failover] failed to send service-error email: %s" % (email_err,))
        raise


async def handle_test_api(request):
    """GET /test-api?domain=... — validated, normalized, single block check."""
    try:
        url_str = str(request.url) if hasattr(request, "url") else ""
        parsed_url = urlparse(url_str)
        query_params = parse_qs(parsed_url.query)
        raw = query_params.get("domain", ["kubatoto88.net"])
        test_domain = (raw[0] if raw else "").strip() or "kubatoto88.net"
    except Exception:
        test_domain = "kubatoto88.net"
    norm = normalize_domain(test_domain)
    if not norm or len(norm) > MAX_DOMAIN_LEN:
        return Response(
            safe_json_dumps({"error": "Invalid or missing domain parameter", "domain": test_domain[:80]}),
            headers=_json_headers(),
            status=400,
        )
    api_url = f"{TRUSTPOSITIF_BASE_URL}/api/check-kominfo?domains={quote_plus(norm)}"
    try:
        response = await js_fetch(api_url, method="GET")
        response_text_js = await response.text()
        response_text = await to_python_text(response_text_js)
    except Exception as e:
        print("[test-api] fetch error: %s" % (e,))
        return Response(
            safe_json_dumps({"error": "Failed to call block-check API", "detail": "Request failed"}),
            headers=_json_headers(),
            status=502,
        )
    try:
        parsed_response = json.loads(response_text)
        parsed_response = js_to_py(parsed_response) if is_jsproxy(parsed_response) else parsed_response
    except Exception:
        parsed_response = None
    result = {
        "status_code": response.status,
        "status_ok": response.ok,
        "api_url": api_url,
        "test_domain": norm,
        "response": response_text,
        "response_parsed": parsed_response,
    }
    return Response(safe_json_dumps(result, indent=2), headers=_json_headers())


async def handle_test():
    """GET /test — hardcoded domains block check."""
    test_domains = ["kubatotosgp.me", "kubatoto88.net"]
    results = []
    blocked_domains = []
    
    for domain in test_domains:
        print(f"Testing domain: {domain}")
        is_blocked, response_data = await check_domain_blocked(domain)
        cleaned_response = ensure_json_serializable(response_data)
        results.append({
            "domain": domain,
            "blocked": is_blocked,
            "api_response": cleaned_response
        })
        if is_blocked:
            blocked_domains.append(("TEST", domain))
    
    result = {
        "status": "success",
        "blocked_count": len(blocked_domains),
        "blocked_domains": [{"domain": d} for _, d in blocked_domains],
        "test_results": results,
        "timestamp": datetime.now().isoformat()
    }
    
    return Response(safe_json_dumps(result, indent=2), headers=_json_headers())


def _request_has_full(request) -> bool:
    """True if the request URL contains ?full=true."""
    try:
        url_str = str(request.url) if request and hasattr(request, "url") else ""
        qs = parse_qs(urlparse(url_str).query)
        return qs.get("full", [""])[0].lower() == "true"
    except Exception:
        return False


async def handle_get_config(env, request=None):
    """GET /api/config — current config JSON. API slot hidden unless ?full=true."""
    config = await get_config(env)
    if not _request_has_full(request):
        active = {k: v for k, v in (config.get("active") or {}).items() if k.upper() != "API"}
        config = dict(config)
        config["active"] = active
    return Response(safe_json_dumps(config, indent=2), headers=_json_headers_read_only())


async def handle_get_active(env, request=None):
    """GET /api/active — active slots only, e.g. { \"FB\": \"https://...\", \"LP\": \"https://...\" }. API slot hidden unless ?full=true."""
    config = await get_config(env)
    active = dict(config.get("active") or {})
    if not _request_has_full(request):
        active = {k: v for k, v in active.items() if k.upper() != "API"}
    return Response(safe_json_dumps(active, indent=2), headers=_json_headers_read_only())


async def handle_get_backups(env):
    """GET /api/backups — backups array only."""
    config = await get_config(env)
    return Response(safe_json_dumps(config.get("backups") or [], indent=2), headers=_json_headers_read_only())


async def handle_put_config(request, env):
    """PUT /api/config — body { active: {}, backups: [] }; 413 if body too large."""
    try:
        body_text_js = await request.text() if hasattr(request, "text") else ""
        body_text = await to_python_text(body_text_js) if body_text_js else ""
        if len(body_text) > MAX_CONFIG_BODY_BYTES:
            return Response(safe_json_dumps({"error": "Request body too large"}), headers=_json_headers(), status=413)
        body = None
        try:
            body = json.loads(body_text) if body_text.strip() else None
        except Exception:
            pass
        if body and is_jsproxy(body):
            body = js_to_py(body)
        if not isinstance(body, dict):
            return Response(safe_json_dumps({"error": "JSON body with active (object) and backups (array) required"}), headers=_json_headers(), status=400)
        ok = await put_config(env, body)
        config = await get_config(env)
        return Response(safe_json_dumps({"ok": ok, "config": config}, indent=2), headers=_json_headers())
    except Exception as e:
        import traceback
        print("[config] put_config error: %s\n%s" % (e, traceback.format_exc()))
        return Response(safe_json_dumps({"error": "Configuration update failed"}), headers=_json_headers(), status=500)


async def handle_run_failover(env):
    """GET /api/run - run failover once and return result."""
    result = await run_failover(env)
    return Response(safe_json_dumps({"status": "success", "result": result, "timestamp": datetime.now().isoformat()}, indent=2), headers=_json_headers())


async def handle_test_email(env):
    """GET /api/test-email - send a test email and return { sent: true } or { sent: false, error: ... }."""
    try:
        ok = await send_email(env, "Test from worker", "If you get this, email works.")
        if ok:
            return Response(safe_json_dumps({"sent": True}), headers=_json_headers())
        return Response(safe_json_dumps({"sent": False, "error": "send_email returned false"}), headers=_json_headers(), status=200)
    except Exception as e:
        print("[email] test endpoint error: %s" % (e,))
        return Response(safe_json_dumps({"sent": False, "error": str(e)}), headers=_json_headers(), status=200)


async def handle_get_status(env):
    """GET /api/status — config plus health/blocked for active domains only."""
    config = await get_config(env)
    active_dict = config.get("active") or {}
    backups_list = config.get("backups") or []
    indexed = [(slot, domain) for slot, domain in (active_dict or {}).items() if domain]
    if not indexed:
        active_status = []
    else:
        slots, domains = zip(*indexed)
        results = await asyncio.gather(*[is_domain_healthy(d) for d in domains], return_exceptions=True)
        active_status = []
        for (slot, domain), result in zip(indexed, results):
            if isinstance(result, Exception):
                healthy, status_code, is_blocked = False, 0, False
            else:
                healthy, status_code, is_blocked = result
            if healthy:
                status_label = "ok"
            elif is_blocked:
                status_label = "blocked"
            else:
                status_label = "down"
            active_status.append({
                "slot": slot,
                "domain": domain,
                "status": status_label,
                "status_code": status_code,
                "blocked": is_blocked,
            })
    payload = {
        "active": active_status,
        "backups": [{"domain": d} for d in backups_list if d],
        "timestamp": datetime.now().isoformat(),
    }
    return Response(safe_json_dumps(payload, indent=2), headers=_json_headers())


def get_ui_html(base_path=""):
    """Config UI HTML. base_path = secret path prefix for API calls."""
    base_path = base_path or ""
    if base_path and not base_path.startswith("/"):
        base_path = "/" + base_path
    api_prefix = "" if base_path else "/api"
    noindex = '<meta name="robots" content="noindex, nofollow">'
    html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  """ + noindex + """
  <title>Domain config</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 1.5rem; background: #0f0f12; color: #e4e4e7; }
    .layout { max-width: 1000px; margin: 0 auto; display: flex; gap: 2rem; align-items: start; }
    .main { flex: 1; min-width: 0; }
    .aside { width: 280px; flex-shrink: 0; position: sticky; top: 1rem; }
    @media (max-width: 820px) { .layout { flex-direction: column; } .aside { width: 100%; position: static; } }
    h1 { font-size: 1.35rem; margin-bottom: 0.25rem; font-weight: 600; }
    .subtitle { color: #71717a; font-size: 0.875rem; margin-bottom: 1.5rem; }
    .card { background: #18181b; border: 1px solid #27272a; border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1rem; }
    .card-title { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #a1a1aa; margin-bottom: 0.75rem; }
    label { display: block; font-size: 0.85rem; margin-bottom: 0.35rem; color: #a1a1aa; }
    textarea { width: 100%; min-height: 88px; padding: 0.6rem; border: 1px solid #3f3f46; border-radius: 6px; background: #0f0f12; color: #e4e4e7; font-family: inherit; font-size: 0.9rem; }
    button { padding: 0.5rem 0.85rem; border-radius: 6px; border: none; font-size: 0.875rem; cursor: pointer; }
    .btn-primary { background: #3b82f6; color: #fff; }
    .btn-primary:hover { background: #2563eb; }
    .btn-secondary { background: #3f3f46; color: #e4e4e7; }
    .btn-secondary:hover { background: #52525b; }
    button:disabled { opacity: 0.7; cursor: not-allowed; }
    .btn-loading { position: relative; }
    .btn-loading .spinner { display: inline-block; width: 0.9em; height: 0.9em; margin-right: 0.35rem; vertical-align: -0.15em; border: 2px solid currentColor; border-right-color: transparent; border-radius: 50%; animation: spin 0.6s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .btn-group { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
    .msg { margin-top: 0.5rem; padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.875rem; }
    .msg.success { background: #14532d; color: #86efac; }
    .msg.error { background: #450a0a; color: #fca5a5; }
    table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
    th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #27272a; }
    th { color: #71717a; font-weight: 500; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.03em; }
    .status-ok { color: #86efac; }
    .status-down { color: #fca5a5; }
    .status-blocked { color: #fbbf24; }
    .slot { color: #71717a; font-size: 0.85rem; }
    .input-domain { flex: 1; min-width: 140px; padding: 0.5rem 0.6rem; border: 1px solid #3f3f46; border-radius: 6px; background: #0f0f12; color: #e4e4e7; font-size: 0.9rem; }
    .json-panel { margin-top: 0.75rem; padding: 0.75rem; background: #0f0f12; border: 1px solid #27272a; border-radius: 6px; }
    .json-panel pre { margin: 0; font-size: 0.8rem; font-family: ui-monospace, monospace; color: #a1a1aa; white-space: pre-wrap; word-break: break-all; max-height: 280px; overflow: auto; }
    .json-panel .json-actions { margin-top: 0.5rem; display: flex; gap: 0.5rem; align-items: center; }
    .json-panel .json-actions a { color: #3b82f6; font-size: 0.85rem; }
    .aside .card { padding: 0.85rem 1rem; }
    .aside .card-title { margin-bottom: 0.5rem; font-size: 0.7rem; }
    .desc { font-size: 0.8rem; color: #71717a; line-height: 1.45; margin: 0; }
    .desc + .card-title { margin-top: 1rem; }
    .desc-item { margin-bottom: 0.6rem; }
    .desc-item strong { color: #a1a1aa; font-size: 0.78rem; }
    .aside code { font-size: 0.75rem; background: #27272a; padding: 0.1rem 0.3rem; border-radius: 3px; }
    .slot-row { display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.5rem; }
    .slot-row input.slot-name { width: 80px; padding: 0.5rem 0.6rem; border: 1px solid #3f3f46; border-radius: 6px; background: #0f0f12; color: #e4e4e7; font-size: 0.9rem; }
    .slot-row input.slot-url { flex: 1; min-width: 120px; padding: 0.5rem 0.6rem; border: 1px solid #3f3f46; border-radius: 6px; background: #0f0f12; color: #e4e4e7; font-size: 0.9rem; }
    .slot-row .btn-remove { padding: 0.35rem 0.5rem; font-size: 0.8rem; background: #450a0a; color: #fca5a5; }
    .slot-row .btn-remove:hover { background: #7f1d1d; }
    .slot-header { display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.35rem; font-size: 0.8rem; color: #71717a; }
    .slot-header .col-label { width: 90px; }
    .slot-header .col-url { flex: 1; min-width: 120px; }
    .card-title-main { font-size: 0.95rem; font-weight: 600; color: #e4e4e7; margin-bottom: 0.35rem; }
    .card-desc { font-size: 0.875rem; color: #71717a; line-height: 1.45; margin-bottom: 0.75rem; }
    .btn-primary { font-weight: 500; }
    .advanced-toggle { font-size: 0.85rem; color: #71717a; cursor: pointer; margin-top: 0.5rem; }
    .advanced-toggle:hover { color: #a1a1aa; }
    button:focus-visible, input:focus-visible, textarea:focus-visible, a:focus-visible { outline: 2px solid #3b82f6; outline-offset: 2px; }
    .advanced-toggle:focus-visible { outline: 2px solid #3b82f6; outline-offset: 2px; }
    .advanced-section { margin-top: 0.5rem; }
    .help-list { margin: 0; padding-left: 1.1rem; color: #71717a; font-size: 0.85rem; line-height: 1.6; }
    .help-list li { margin-bottom: 0.35rem; }
  </style>
</head>
<body>
  <div class="layout">
  <div class="main">
  <h1>Link Monitor</h1>
  <div class="card">
    <div class="card-title-main">Your Main Links</div>
    <p class="card-desc">These are the links that are checked regularly. Give each one a short label (e.g. Home, Blog, Shop) and the full website address.</p>
    <div class="slot-header">
      <span class="col-label">Label</span>
      <span class="col-url">Website address</span>
    </div>
    <div id="activeSlots"></div>
    <div class="btn-group" style="margin-top: 0.5rem;">
      <button class="btn-secondary" id="addSlot" type="button">+ Add another link</button>
    </div>
  </div>
  <div class="card">
    <div class="card-title-main">Backup Links</div>
    <p class="card-desc">If a main link stops working, one of these can take its place. Enter one website per line.</p>
    <label for="backups" style="margin-bottom: 0.25rem;">Website addresses (one per line)</label>
    <textarea id="backups" placeholder="https://backup-site.com&#10;https://another-backup.com" rows="3"></textarea>
  </div>

  <div class="card">
    <div class="card-title-main">Save and Run</div>
    <p class="card-desc">Load your saved settings first, then edit. When done, save. Use &quot;Check links now&quot; to run a check immediately.</p>
    <div class="btn-group">
      <button class="btn-secondary" id="load">Load my saved settings</button>
      <button class="btn-primary" id="save">Save changes</button>
      <button class="btn-secondary" id="run">Check links now</button>
    </div>
    <div id="msg"></div>
  </div>

  <div class="card">
    <div class="card-title-main">Quick Add</div>
    <p class="card-desc">Type a website address below, then choose whether to add it as a main link or a backup link.</p>
    <div class="btn-group">
      <input type="text" id="newDomain" placeholder="https://example.com" class="input-domain" aria-label="Website address to add as main or backup link" />
      <button class="btn-secondary" id="addActive">Add as main link</button>
      <button class="btn-secondary" id="addBackup">Add as backup link</button>
    </div>
  </div>

  <div class="card">
    <button type="button" class="advanced-toggle" id="advancedToggle" aria-expanded="false" aria-controls="advancedSection">▼ More options (backup file, raw data)</button>
    <div id="advancedSection" class="advanced-section" style="display: none;" role="region" aria-label="Extra options">
      <div class="btn-group" style="margin-top: 0.5rem;">
        <button class="btn-secondary" id="downloadJson">Download backup file</button>
        <button class="btn-secondary" id="viewJson">View raw data</button>
      </div>
      <div id="jsonPanel" class="json-panel" style="display: none; margin-top: 0.5rem;">
        <pre id="jsonContent"></pre>
        <div class="json-actions">
          <button class="btn-secondary" id="copyJson" type="button">Copy</button>
          <a id="openJsonTab" href="#" target="_blank" rel="noopener">Open in new tab</a>
        </div>
      </div>
      <div style="margin-top: 1rem;">
        <label for="resetJson">Replace all settings (paste data)</label>
        <textarea id="resetJson" placeholder='Paste backup data here, then click Reset.' rows="3"></textarea>
        <div class="btn-group" style="margin-top: 0.5rem;">
          <button class="btn-secondary" id="resetConfig">Reset from pasted data</button>
        </div>
      </div>
    </div>
  </div>

  </div>
  <aside class="aside">
    <div class="card">
      <div class="card-title-main">Need help?</div>
      <ul class="help-list">
        <li><strong>Main links</strong> — The links you use (e.g. for Home, Blog). Each needs a label and full address.</li>
        <li><strong>Backup links</strong> — Spare links that can replace a main link if it goes down.</li>
        <li><strong>Load</strong> — Bring your last saved settings into the form.</li>
        <li><strong>Save</strong> — Store your changes. Do this after editing so the system uses your list.</li>
        <li><strong>Check links now</strong> — Run a check once (the system also runs checks automatically on a schedule).</li>
      </ul>
    </div>
  </aside>
  </div>
  <script>
    const base = location.origin + "__BASE_PATH__";
    const apiPrefix = "__API_PREFIX__";
    function msg(s, isError) {
      const el = document.getElementById('msg');
      el.textContent = s;
      el.className = 'msg ' + (isError ? 'error' : 'success');
    }
    function createSlotRow(slotName, slotUrl) {
      const div = document.createElement('div');
      div.className = 'slot-row';
      const slotInput = document.createElement('input');
      slotInput.type = 'text';
      slotInput.className = 'slot-name';
      slotInput.placeholder = 'e.g. Home';
      slotInput.setAttribute('aria-label', 'Link label');
      slotInput.value = slotName || '';
      const urlInput = document.createElement('input');
      urlInput.type = 'text';
      urlInput.className = 'slot-url';
      urlInput.placeholder = 'https://yoursite.com';
      urlInput.setAttribute('aria-label', 'Website address');
      urlInput.value = slotUrl || '';
      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'btn-secondary btn-remove';
      removeBtn.textContent = 'Remove';
      removeBtn.setAttribute('aria-label', 'Remove this link');
      removeBtn.onclick = function () { div.remove(); };
      div.appendChild(slotInput);
      div.appendChild(urlInput);
      div.appendChild(removeBtn);
      return div;
    }
    function getActiveFromSlots() {
      const container = document.getElementById('activeSlots');
      const active = {};
      for (let i = 0; i < container.children.length; i++) {
        const row = container.children[i];
        const slotIn = row.querySelector('input.slot-name');
        const urlIn = row.querySelector('input.slot-url');
        if (slotIn && urlIn) {
          const k = (slotIn.value || '').trim();
          const v = (urlIn.value || '').trim();
          if (k && v) active[k] = v;
        }
      }
      return active;
    }
    function setActiveSlots(activeObj) {
      const container = document.getElementById('activeSlots');
      container.innerHTML = '';
      const entries = activeObj && typeof activeObj === 'object' && !Array.isArray(activeObj) ? Object.entries(activeObj) : [];
      if (entries.length === 0) {
        container.appendChild(createSlotRow('', ''));
      } else {
        entries.forEach(function (e) { container.appendChild(createSlotRow(e[0], e[1])); });
      }
    }
    function getBackupsFromTextarea() {
      return document.getElementById('backups').value.trim().split(/\\n+/).filter(Boolean);
    }
    function escapeHtml(str) {
      const div = document.createElement('div');
      div.textContent = str;
      return div.innerHTML;
    }
    function setBtnLoading(btn, loading, loadingText) {
      if (!btn) return;
      if (loading) {
        if (!btn.classList.contains('btn-loading')) {
          btn.dataset.originalText = btn.textContent;
        }
        btn.disabled = true;
        btn.classList.add('btn-loading');
        btn.innerHTML = '<span class="spinner"></span>' + loadingText;
      } else {
        btn.disabled = false;
        btn.classList.remove('btn-loading');
        btn.textContent = btn.dataset.originalText || btn.textContent;
      }
    }
    async function responseJson(r) {
      const text = await r.text();
      if (!r.ok) throw new Error(text ? text.slice(0, 200) : 'Request failed ' + r.status);
      try { return JSON.parse(text); } catch (e) {
        throw new Error(text ? ('Server returned non-JSON: ' + text.slice(0, 150)) : 'Empty response');
      }
    }
    var REQUEST_TIMEOUT_MS = 25000;
    function fetchWithTimeout(url, opts, timeoutMs) {
      timeoutMs = timeoutMs || REQUEST_TIMEOUT_MS;
      var ctrl = new AbortController();
      var t = setTimeout(function () { ctrl.abort(); }, timeoutMs);
      var optsCopy = opts ? Object.assign({}, opts) : {};
      optsCopy.signal = ctrl.signal;
      return fetch(url, optsCopy).then(function (r) {
        clearTimeout(t);
        return r;
      }, function (err) {
        clearTimeout(t);
        if (err.name === 'AbortError') throw new Error('Request timed out. Try again.');
        throw err;
      });
    }
    function isWorkerRestartedError(e) {
      return e && e.message && e.message.indexOf('worker restarted') !== -1;
    }
    async function withRetry(fn, btn, loadingText) {
      const maxAttempts = 2;
      let lastErr;
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        if (attempt > 0) {
          setBtnLoading(btn, true, 'Retrying…');
          await new Promise(function (r) { setTimeout(r, 1500); });
        }
        try {
          return await fn();
        } catch (e) {
          lastErr = e;
          if (isWorkerRestartedError(e) && attempt < maxAttempts - 1) continue;
          throw e;
        }
      }
      throw lastErr;
    }
    async function load() {
      const btn = document.getElementById('load');
      setBtnLoading(btn, true, 'Loading…');
      try {
        await withRetry(async function () {
          const r = await fetchWithTimeout(base + apiPrefix + '/config');
          const c = await responseJson(r);
          const active = c.active && typeof c.active === 'object' && !Array.isArray(c.active) ? c.active : {};
          setActiveSlots(active);
          document.getElementById('backups').value = (c.backups || []).join('\\n');
          msg('Your saved settings are loaded.');
        }, btn, 'Loading…');
      } catch (e) {
        msg('Load failed: ' + e.message, true);
      } finally {
        setBtnLoading(btn, false);
      }
    }
    async function save() {
      const btn = document.getElementById('save');
      setBtnLoading(btn, true, 'Saving…');
      try {
        await withRetry(async function () {
          const active = getActiveFromSlots();
          const backups = getBackupsFromTextarea();
          const r = await fetchWithTimeout(base + apiPrefix + '/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ active, backups }) });
          const data = await responseJson(r);
          if (data.error) throw new Error(data.error);
          msg('Changes saved.');
          refreshJsonPanel({ active: active, backups: backups });
        }, btn, 'Saving…');
      } catch (e) {
        msg('Save failed: ' + e.message, true);
      } finally {
        setBtnLoading(btn, false);
      }
    }
    async function runFailover() {
      const btn = document.getElementById('run');
      setBtnLoading(btn, true, 'Running…');
      try {
        await withRetry(async function () {
          const r = await fetchWithTimeout(base + apiPrefix + '/run', {}, 90000);
          const data = await responseJson(r);
          var res = data.result || {};
          if (res.active != null && res.backups) {
            setActiveSlots(res.active);
            document.getElementById('backups').value = res.backups.join('\\n');
            refreshJsonPanel({ active: res.active, backups: res.backups });
          }
          var n = (res.changes && res.changes.length) || 0;
          var d = (res.down_slots && res.down_slots.length) || 0;
          if (n === 0 && d === 0) msg('Done. All links OK; no changes needed.');
          else if (n > 0) msg('Done. ' + n + ' link(s) were replaced.');
          else msg('Done. ' + d + ' link(s) are down; check backup links.');
        }, btn, 'Running…');
      } catch (e) {
        msg('Run failed: ' + e.message, true);
      } finally {
        setBtnLoading(btn, false);
      }
    }
    function addToActive() {
      const v = document.getElementById('newDomain').value.trim();
      document.getElementById('activeSlots').appendChild(createSlotRow('', v || ''));
      if (v) document.getElementById('newDomain').value = '';
    }
    function addToBackup() {
      const v = document.getElementById('newDomain').value.trim();
      if (!v) return;
      const ta = document.getElementById('backups');
      ta.value = (ta.value.trim() ? ta.value.trim() + '\\n' : '') + v;
      document.getElementById('newDomain').value = '';
    }
    async function resetConfig() {
      const raw = document.getElementById('resetJson').value.trim();
      if (!raw) { msg('Paste your backup data first.', true); return; }
      const btn = document.getElementById('resetConfig');
      setBtnLoading(btn, true, 'Resetting…');
      try {
        const c = JSON.parse(raw);
        let active = c.active;
        if (Array.isArray(active)) {
          const converted = {};
          active.forEach(function (d, i) { converted[String(i + 1)] = String(d).trim(); });
          active = converted;
        }
        if (!active || typeof active !== 'object') active = {};
        const backups = Array.isArray(c.backups) ? c.backups.map(String).filter(Boolean) : [];
        await withRetry(async function () {
          const r = await fetchWithTimeout(base + apiPrefix + '/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ active, backups }) });
          const data = await responseJson(r);
          if (data.error) throw new Error(data.error);
          setActiveSlots(active);
          document.getElementById('backups').value = backups.join('\\n');
          msg('Settings reset from pasted data.');
          refreshJsonPanel({ active: active, backups: backups });
        }, btn, 'Resetting…');
      } catch (e) {
        msg('Reset failed. Check that you pasted a full backup (e.g. from a downloaded backup file).', true);
      } finally {
        setBtnLoading(btn, false);
      }
    }
    function downloadJson() {
      const active = getActiveFromSlots();
      const backups = getBackupsFromTextarea();
      const json = JSON.stringify({ active: active, backups: backups }, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'domain-config.json';
      a.click();
      URL.revokeObjectURL(url);
      msg('Backup file downloaded.');
    }
    function refreshJsonPanel(cfg) {
      const panel = document.getElementById('jsonPanel');
      if (panel.style.display === 'none') return;
      const pre = document.getElementById('jsonContent');
      if (!cfg) cfg = { active: getActiveFromSlots(), backups: getBackupsFromTextarea() };
      pre.textContent = JSON.stringify({ active: cfg.active || {}, backups: cfg.backups || [] }, null, 2);
    }
    function viewJson() {
      const panel = document.getElementById('jsonPanel');
      const pre = document.getElementById('jsonContent');
      const active = getActiveFromSlots();
      const backups = getBackupsFromTextarea();
      const json = JSON.stringify({ active: active, backups: backups }, null, 2);
      pre.textContent = json;
      document.getElementById('openJsonTab').href = base + apiPrefix + '/config';
      if (panel.style.display === 'none') {
        panel.style.display = 'block';
      } else {
        panel.style.display = 'none';
      }
    }
    function copyJson() {
      const pre = document.getElementById('jsonContent');
      if (!pre.textContent) return;
      navigator.clipboard.writeText(pre.textContent).then(function () { msg('Copied to clipboard'); }).catch(function () { msg('Copy failed', true); });
    }
    document.getElementById('addSlot').onclick = function () {
      document.getElementById('activeSlots').appendChild(createSlotRow('', ''));
    };
    document.getElementById('advancedToggle').onclick = function () {
      var el = document.getElementById('advancedSection');
      var toggle = document.getElementById('advancedToggle');
      var open = el.style.display !== 'none';
      el.style.display = open ? 'none' : 'block';
      toggle.textContent = open ? '▼ More options (backup file, raw data)' : '▲ Hide extra options';
      toggle.setAttribute('aria-expanded', open ? 'false' : 'true');
    };
    document.getElementById('advancedToggle').onkeydown = function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); this.click(); }
    };
    document.getElementById('load').onclick = load;
    document.getElementById('save').onclick = save;
    document.getElementById('downloadJson').onclick = downloadJson;
    document.getElementById('viewJson').onclick = viewJson;
    document.getElementById('copyJson').onclick = copyJson;
    document.getElementById('run').onclick = runFailover;
    document.getElementById('addActive').onclick = addToActive;
    document.getElementById('addBackup').onclick = addToBackup;
    document.getElementById('resetConfig').onclick = resetConfig;
    load();
  </script>
</body>
</html>"""
    return html.replace("__BASE_PATH__", base_path).replace("__API_PREFIX__", api_prefix)


async def _handle_login_post(request, base_path: str, creds):
    """Parse form body, verify credentials, return (Response with redirect + cookie) or (None, error_str)."""
    try:
        body_js = await request.text() if hasattr(request, "text") else ""
        body = await to_python_text(body_js) if body_js else ""
    except Exception:
        return get_login_html(base_path, "error"), None
    data = parse_qs(body, keep_blank_values=True)
    user = (data.get("user") or [""])[0]
    password = (data.get("pass") or [""])[0]
    if not _verify_password(user, password, creds):
        return get_login_html(base_path, "invalid"), None
    admin_user, _, session_secret = creds
    cookie_val = _make_session_cookie(admin_user, base_path, session_secret)
    path_for_cookie = base_path if base_path else "/"
    cookie = "%s=%s; Path=%s; Max-Age=%d; HttpOnly; Secure; SameSite=Strict" % (
        SESSION_COOKIE_NAME, cookie_val, path_for_cookie, SESSION_TTL_SEC
    )
    location = base_path if base_path else "/"
    if not location.startswith("/"):
        location = "/" + location
    headers = {"Location": location, "Set-Cookie": cookie, **_security_headers()}
    return None, Response("", status=302, headers=headers)


async def on_fetch(request, env, ctx):
    try:
        url = str(request.url) if hasattr(request, 'url') else ''
    except Exception:
        url = ''
    path = urlparse(url).path if url else ''
    method = (getattr(request, "method", None) or "GET").upper()
    print("[fetch] %s %s" % (method, path or "/"))

    if method == "OPTIONS":
        return Response("", status=204, headers={"Allow": "GET, POST, PUT, OPTIONS"})

    try:
        secret = _get_secret_path(env)
        base_path, inner = _path_resolve(path, secret)
        if secret and base_path is None:
            return Response("Not Found", status=404, headers={"Content-Type": "text/plain"})

        creds = _get_auth_credentials(env)
        protected = ("__ui__", "status", "run", "test-email")

        if inner == LOGIN_INNER:
            if not creds:
                loc = base_path if base_path else "/"
                return Response("", status=302, headers={"Location": loc, **_security_headers()})
            if method == "POST":
                login_html, redirect_resp = await _handle_login_post(request, base_path or "", creds)
                if redirect_resp is not None:
                    return redirect_resp
                return Response(login_html, status=401, headers={"content-type": "text/html;charset=UTF-8", **_security_headers()})
            return Response(get_login_html(base_path or ""), headers={"content-type": "text/html;charset=UTF-8", **_security_headers()})

        if creds and inner in protected and not _is_authenticated(request, base_path or "", creds):
            if inner == "__ui__" and method == "GET":
                return Response(get_login_html(base_path or ""), status=401, headers={"content-type": "text/html;charset=UTF-8", **_security_headers()})
            return Response(safe_json_dumps({"error": "Unauthorized", "message": "Login required"}), status=401, headers={"Content-Type": "application/json", **_security_headers()})

        if inner == "__ui__":
            resp = Response(get_ui_html(base_path or ""), headers={"content-type": "text/html;charset=UTF-8", **_security_headers()})
            return resp
        if inner == "config":
            if method in ("PUT", "POST"):
                return await handle_put_config(request, env)
            return await handle_get_config(env, request)
        if inner == "active":
            return await handle_get_active(env, request)
        if inner == "backups":
            return await handle_get_backups(env)
        if inner == "status":
            return await handle_get_status(env)
        if inner == "run":
            return await handle_run_failover(env)
        if inner == "test-email" and method == "GET":
            return await handle_test_email(env)
        if inner == "test-api":
            return await handle_test_api(request)
        if inner == "test":
            return await handle_test()
        if inner is None:
            return Response(
                "Domain failover worker. Set SECRET_PATH (env/var) to hide UI under /{secret}/. Public (no auth): /active, /backups, /config. Protected: status, run, test-email, UI.",
                headers={"Content-Type": "text/plain"}
            )
        return Response("Not Found", status=404, headers={"Content-Type": "text/plain"})
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print("[fetch] error: %s" % (e,))
        print("[fetch] traceback: %s" % (error_trace,))
        return Response(safe_json_dumps({
            "status": "error",
            "message": str(e)
        }), headers=_json_headers(), status=500)
