import threading
import time

from app import config

_redis = None
_mem = {}
_lock = threading.Lock()


def redis_client():
    global _redis
    if _redis is None and config.REDIS_URL:
        import redis
        _redis = redis.Redis.from_url(config.REDIS_URL, socket_timeout=0.5, socket_connect_timeout=0.5, decode_responses=True)
    return _redis


def _purge(now):
    for k in [k for k, (exp, _) in _mem.items() if exp and exp < now]:
        _mem.pop(k, None)


def set_ex(key, value, ttl):
    r = redis_client()
    if r is not None:
        try:
            r.set(key, value, ex=ttl)
            return
        except Exception:
            pass
    with _lock:
        _mem[key] = (time.time() + ttl, value)


def get(key):
    r = redis_client()
    if r is not None:
        try:
            return r.get(key)
        except Exception:
            pass
    with _lock:
        hit = _mem.get(key)
        if hit and (not hit[0] or hit[0] > time.time()):
            return hit[1]
    return None


def getdel(key):
    r = redis_client()
    if r is not None:
        try:
            return r.getdel(key)
        except Exception:
            pass
    with _lock:
        hit = _mem.pop(key, None)
        if hit and (not hit[0] or hit[0] > time.time()):
            return hit[1]
    return None


def incr(key, ttl):
    r = redis_client()
    if r is not None:
        try:
            p = r.pipeline()
            p.incr(key)
            p.expire(key, ttl, nx=True)
            return int(p.execute()[0])
        except Exception:
            pass
    with _lock:
        now = time.time()
        _purge(now)
        exp, val = _mem.get(key, (now + ttl, 0))
        _mem[key] = (exp, val + 1)
        return val + 1


def delete(key):
    r = redis_client()
    if r is not None:
        try:
            r.delete(key)
        except Exception:
            pass
    with _lock:
        _mem.pop(key, None)


def reset_memory():
    with _lock:
        _mem.clear()
