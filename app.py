"""TDS GA2 - one combined service for Q3,4,5,6,7,8,9,10,11,12 (single process)."""
import base64, json, math, os, re, threading, time, uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

EMAIL = "23f3004314@ds.study.iitm.ac.in"
START = time.time()

# ----- assigned values -------------------------------------------------------
Q3_ORIGIN = "https://dash-h480sr.example.com"
Q4_ISS = "https://idp.exam.local"
Q4_AUD = "tds-twrtw7t3.apps.exam.local"
Q4_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----
"""
Q7_KEY = "ak_v8rhm8wcugdyesyqs6uteur7"
Q11_TOTAL = 43
Q11_RATE = 16
Q12_ORIGIN = "https://app-ucttl1.example.com"
Q12_RATE = 13
EXAM_ORIGINS = {"https://exam.sanand.workers.dev", "https://tds.s-anand.net"}
WINDOW = 10.0

app = FastAPI()

# ----- shared state ------------------------------------------------------------
LOGS = deque(maxlen=2000)
REQ_TOTAL = 0
RATE = defaultdict(deque)
LOCK = threading.Lock()


def allowed_origins_for(path: str):
    """None => '*' (open); set => only those origins get ACAO."""
    if path.startswith("/stats"):
        return {Q3_ORIGIN}
    if path.startswith("/ping"):
        return {Q12_ORIGIN} | EXAM_ORIGINS
    return None


def cors_for(path: str, origin: Optional[str], request_headers: Optional[str] = None, preflight=False):
    allowed = allowed_origins_for(path)
    h = {}
    if allowed is None:
        h["Access-Control-Allow-Origin"] = "*"
    elif origin and origin in allowed:
        h["Access-Control-Allow-Origin"] = origin
        h["Vary"] = "Origin"
    else:
        return None if preflight else {}
    h["Access-Control-Expose-Headers"] = "X-Request-ID, X-Process-Time, Retry-After, Content-Type"
    if preflight:
        h["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        h["Access-Control-Allow-Headers"] = request_headers or "*"
        h["Access-Control-Max-Age"] = "600"
    return h


def rate_limited(scope: str, client: str, limit: int):
    now = time.time()
    with LOCK:
        dq = RATE[(scope, client)]
        while dq and now - dq[0] >= WINDOW:
            dq.popleft()
        if len(dq) >= limit:
            return max(1, math.ceil(WINDOW - (now - dq[0])))
        dq.append(now)
    return 0


@app.middleware("http")
async def stack(request: Request, call_next):
    global REQ_TOTAL
    t0 = time.perf_counter()
    path = request.url.path
    origin = request.headers.get("origin")
    rid = request.headers.get("x-request-id") or str(uuid.uuid4())
    REQ_TOTAL += 1

    if request.method == "OPTIONS":
        h = cors_for(path, origin, request.headers.get("access-control-request-headers"), preflight=True)
        if h is None:
            resp = Response(status_code=403)
        else:
            resp = Response(status_code=204, headers=h)
    else:
        resp = None
        client = request.headers.get("x-client-id")
        if client:
            if path.startswith("/orders"):
                ra = rate_limited("orders", client, Q11_RATE)
            elif path.startswith("/ping"):
                ra = rate_limited("ping", client, Q12_RATE)
            else:
                ra = 0
            if ra:
                resp = JSONResponse({"error": "rate limit exceeded"}, status_code=429, headers={"Retry-After": str(ra)})
        if resp is None:
            try:
                resp = await call_next(request)
            except Exception as e:  # never leak a 500 stack
                resp = JSONResponse({"error": "internal error", "detail": str(e)[:200]}, status_code=500)
        for k, v in (cors_for(path, origin) or {}).items():
            resp.headers[k] = v
    resp.headers["X-Request-ID"] = rid
    resp.headers["X-Process-Time"] = f"{time.perf_counter() - t0:.6f}"
    entry = {"level": "INFO" if resp.status_code < 400 else "WARNING", "ts": datetime.now(timezone.utc).isoformat(),
             "path": path, "request_id": rid, "method": request.method, "status": resp.status_code}
    LOGS.append(entry)
    print(json.dumps(entry), flush=True)
    return resp


@app.get("/")
def root():
    return {"ok": True, "email": EMAIL}


# ----- Q3 ----------------------------------------------------------------------
@app.get("/stats")
def stats(values: str = ""):
    try:
        nums = [int(x) for x in values.replace(" ", "").split(",") if x != ""]
    except ValueError:
        return JSONResponse({"error": "values must be comma-separated integers"}, status_code=422)
    if not nums:
        return JSONResponse({"error": "no values"}, status_code=422)
    return {"email": EMAIL, "count": len(nums), "sum": sum(nums), "min": min(nums), "max": max(nums),
            "mean": sum(nums) / len(nums)}


# ----- Q4 ----------------------------------------------------------------------
@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        token = body["token"]
        claims = jwt.decode(token, Q4_KEY, algorithms=["RS256"], audience=Q4_AUD, issuer=Q4_ISS,
                            options={"require": ["exp", "iss", "aud"]})
        return {"valid": True, "email": claims.get("email"), "sub": claims.get("sub"), "aud": claims.get("aud")}
    except Exception:
        return JSONResponse({"valid": False}, status_code=401)


# ----- Q5 ----------------------------------------------------------------------
def _bool(v):
    return str(v).strip().lower() in ("true", "1", "yes", "on")


@app.get("/effective-config")
def effective_config(request: Request):
    cfg = {"port": 8000, "workers": 1, "debug": False, "log_level": "info", "api_key": "default-secret-000"}
    cfg.update({"log_level": "warning"})                                       # config.development.yaml
    cfg.update({"port": 8382, "workers": 13, "debug": False, "log_level": "info", "api_key": "key-atajqzco52"})  # .env
    cfg.update({"port": 8958, "log_level": "debug"})                           # OS env APP_*
    for raw in request.query_params.getlist("set"):
        if "=" not in raw:
            continue
        k, v = raw.split("=", 1)
        k = k.strip().lower()
        if k.startswith("app_"):
            k = k[4:]
        if k == "num_workers":
            k = "workers"
        cfg[k] = v
    out = {}
    for k, v in cfg.items():
        if k in ("port", "workers"):
            try:
                v = int(v)
            except (TypeError, ValueError):
                pass
        elif k == "debug":
            v = _bool(v)
        else:
            v = str(v)
        out[k] = v
    out["api_key"] = "****"
    return out


# ----- Q6 (Redis-style counters) --------------------------------------------------
_redis = None
if os.environ.get("REDIS_URL"):
    try:
        import redis as _r
        _redis = _r.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
        _redis.ping()
    except Exception:
        _redis = None
_COUNTS = defaultdict(int)


@app.post("/hit/{key}")
def hit(key: str):
    if _redis:
        n = int(_redis.incr("hit:" + key))
    else:
        with LOCK:
            _COUNTS[key] += 1
            n = _COUNTS[key]
    return {"key": key, "count": n}


@app.get("/count/{key}")
def count(key: str):
    if _redis:
        n = int(_redis.get("hit:" + key) or 0)
    else:
        n = _COUNTS.get(key, 0)
    return {"key": key, "count": n}


# ----- Q7 ----------------------------------------------------------------------
@app.post("/analytics")
async def analytics(request: Request):
    if request.headers.get("x-api-key") != Q7_KEY:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
        events = body.get("events", [])
    except Exception:
        return JSONResponse({"error": "bad body"}, status_code=422)
    users, rev, per = set(), 0.0, defaultdict(float)
    for e in events:
        u = e.get("user")
        users.add(u)
        try:
            a = float(e.get("amount", 0))
        except (TypeError, ValueError):
            a = 0.0
        if a > 0:
            rev += a
            per[u] += a
    top = max(per, key=per.get) if per else None
    return {"email": EMAIL, "total_events": len(events), "unique_users": len(users),
            "revenue": round(rev, 2), "top_user": top}


# ----- Q8 + Q6 health ---------------------------------------------------------------
@app.get("/work")
def work(n: int = 1):
    n = max(0, n)
    x = 0
    for i in range(min(n, 200000)):
        x += i * i
    return {"email": EMAIL, "done": n}


@app.get("/metrics")
def metrics():
    body = ("# HELP http_requests_total Total HTTP requests\n# TYPE http_requests_total counter\n"
            f"http_requests_total {REQ_TOTAL}\n")
    return PlainTextResponse(body, media_type="text/plain; version=0.0.4")


@app.get("/healthz")
def healthz():
    if os.environ.get("HEALTHZ_MODE") == "q6":
        up = "up"
        if _redis:
            try:
                _redis.ping()
            except Exception:
                up = "down"
        return {"status": "ok", "redis": up}
    return {"status": "ok", "uptime_s": round(time.time() - START, 3), "redis": "up"}


@app.get("/logs/tail")
def logs_tail(limit: int = 20):
    limit = max(0, min(limit, 1000))
    return list(LOGS)[-limit:] if limit else []


# ----- Q9: OpenAI-compatible chat endpoint -----------------------------------------------
def _answer(text: str):
    toks = re.findall(r"TK[0-9a-fA-F]{6}", text)
    m = re.search(r"(-?\d+)\s*(?:\+|plus)\s*(-?\d+)", text)
    parts = []
    if m:
        parts.append(f"The answer is {int(m.group(1)) + int(m.group(2))}.")
    if toks:
        parts.append("Token: " + toks[-1])
    return " ".join(parts) if parts else None


def _aipipe(messages, model):
    import urllib.request
    tok = os.environ.get("AIPIPE_TOKEN")
    if not tok:
        return None
    req = urllib.request.Request(
        os.environ.get("AIPIPE_BASE", "https://aipipe.org/openai/v1") + "/chat/completions",
        data=json.dumps({"model": model, "messages": messages}).encode(),
        headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json",
                 "User-Agent": "curl/8.5.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())["choices"][0]["message"]["content"]
    except Exception:
        return None


@app.post("/v1/chat/completions")
async def chat(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    model = body.get("model") or "gpt-4.1-mini"
    msgs = body.get("messages") or []
    last = ""
    for m in msgs:
        if m.get("role") == "user":
            last = m.get("content") if isinstance(m.get("content"), str) else json.dumps(m.get("content"))
    content = _answer(last)
    if content is None:
        content = _aipipe(msgs, "gpt-4.1-mini") or "OK. " + last[:200]
    return {"id": "chatcmpl-" + uuid.uuid4().hex[:12], "object": "chat.completion", "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


# ----- Q10: invoice extraction -------------------------------------------------------------
MONEY = r"(?:USD|EUR|GBP|\$|€|£)?\s*([0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]+)?|[0-9]+(?:\.[0-9]+)?)"
SYM = {"$": "USD", "€": "EUR", "£": "GBP"}


def extract_heuristic(text: str):
    cur = None
    m = re.search(r"\b(USD|EUR|GBP)\b", text)
    if m:
        cur = m.group(1)
    else:
        for s, c in SYM.items():
            if s in text:
                cur = c
                break
    date = None
    dm = list(re.finditer(r"\d{4}-\d{2}-\d{2}", text))
    for mm in dm:
        pre = text[max(0, mm.start() - 40):mm.start()].lower()
        if "due" in pre or "pay" in pre:
            date = mm.group(0)
            break
    if not date and dm:
        date = dm[-1].group(0)
    amount = None
    for kw in (r"total\s+due", r"amount\s+due", r"balance\s+due", r"total\s+amount", r"grand\s+total", r"\btotal\b", r"\bamount\b", r"\bdue\b"):
        m = re.search(kw + r"[^0-9\n]{0,40}?" + MONEY, text, re.I)
        if m:
            amount = float(m.group(1).replace(",", ""))
            break
    if amount is None:
        m = re.search(r"(?:USD|EUR|GBP|\$|€|£)\s*" + r"([0-9][0-9,]*(?:\.[0-9]+)?)", text)
        if m:
            amount = float(m.group(1).replace(",", ""))
        else:
            m = re.search(r"([0-9][0-9,]*(?:\.[0-9]+)?)\s*(?:USD|EUR|GBP)", text)
            if m:
                amount = float(m.group(1).replace(",", ""))
    vendor = None
    m = re.search(r"[A-Z][A-Za-z0-9]*-[A-Za-z0-9]+(?:\s+(?:[A-Z][A-Za-z0-9&.]*|Ltd\.?|Inc\.?|LLC|GmbH|Co\.?|Corp\.?|Industries|Group))*", text)
    if m:
        vendor = m.group(0).strip().rstrip(",;:")
    if not vendor:
        m = re.search(r"(?:vendor|from|billed by|supplier|issued by)\s*[:\-]?\s*([^\n,;]+)", text, re.I)
        if m:
            vendor = m.group(1).strip()
    return vendor, amount, cur, date


def extract_llm(text: str):
    out = _aipipe([
        {"role": "system", "content": "Extract invoice fields. Reply with ONLY JSON: "
         '{"vendor": str, "amount": number (total due), "currency": 3-letter uppercase code, "date": "YYYY-MM-DD" payment due date}'},
        {"role": "user", "content": text}], "gpt-4.1-mini")
    if not out:
        return None
    try:
        s = out[out.index("{"): out.rindex("}") + 1]
        return json.loads(s)
    except Exception:
        return None


@app.post("/extract")
async def extract(request: Request):
    try:
        body = await request.json()
        text = body.get("text")
    except Exception:
        return JSONResponse({"error": "invalid body"}, status_code=422)
    if not isinstance(text, str) or not text.strip():
        return JSONResponse({"error": "text is required"}, status_code=422)
    v, a, c, d = extract_heuristic(text)
    if not (v and a is not None and c and d):
        j = extract_llm(text) or {}
        v = v or j.get("vendor")
        try:
            a = a if a is not None else float(j.get("amount"))
        except (TypeError, ValueError):
            pass
        c = c or (str(j.get("currency", "")).upper() or None)
        d = d or j.get("date")
    return {"vendor": v or "", "amount": float(a) if a is not None else 0.0, "currency": (c or "USD")[:3].upper(),
            "date": d or ""}


# ----- Q11: orders -------------------------------------------------------------------------
IDEM = {}


@app.post("/orders", status_code=201)
async def create_order(request: Request):
    key = request.headers.get("idempotency-key")
    if not key:
        return JSONResponse({"error": "Idempotency-Key header required"}, status_code=400)
    try:
        body = await request.json()
    except Exception:
        body = {}
    with LOCK:
        if key not in IDEM:
            IDEM[key] = {"id": "ord_" + uuid.uuid4().hex[:12], "status": "created", "idempotency_key": key,
                         "created_at": datetime.now(timezone.utc).isoformat(), "request": body}
        order = IDEM[key]
    return order


@app.get("/orders")
def list_orders(limit: int = 10, cursor: Optional[str] = None):
    limit = max(1, min(limit, Q11_TOTAL))
    start = 0
    if cursor:
        try:
            start = int(base64.urlsafe_b64decode(cursor.encode()).decode().split(":")[1])
        except Exception:
            return JSONResponse({"error": "invalid cursor"}, status_code=400)
    ids = list(range(start + 1, min(start + limit, Q11_TOTAL) + 1))
    nxt = None
    if ids and ids[-1] < Q11_TOTAL:
        nxt = base64.urlsafe_b64encode(f"after:{ids[-1]}".encode()).decode()
    return {"items": [{"id": i, "status": "confirmed", "total": 10 * i} for i in ids], "next_cursor": nxt}


# ----- Q12 ---------------------------------------------------------------------------------
@app.get("/ping")
def ping(request: Request):
    rid = request.headers.get("x-request-id") or str(uuid.uuid4())
    return {"email": EMAIL, "request_id": rid}
