import logging

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
csrf = CSRFProtect()


def log_breach(limit):
    logging.getLogger("stepca_web.audit").warning("rate limit %s reached by %s", limit.limit, get_remote_address())


# Keyed by the client address (the real one behind a proxy when TRUSTED_PROXIES is set);
# counters live in RATELIMIT_STORAGE_URI, memory:// by default
limiter = Limiter(get_remote_address, on_breach=log_breach)

# Only the app's own files: no inline script or style, no CDN. Scripts may still set styles through
# the CSSOM (element.style), which CSP allows
CONTENT_SECURITY_POLICY = {
    "default-src": "'self'",
    "script-src": "'self'",
    "style-src": "'self'",
    "img-src": ["'self'", "data:"],
    "font-src": "'self'",
    "connect-src": "'self'",
    "object-src": "'none'",
    "base-uri": "'self'",
    "form-action": "'self'",
    "frame-ancestors": "'none'",
}
