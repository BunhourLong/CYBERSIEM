import os

# ruleid: no-default-session-secret
a = os.getenv("SESSION_SECRET", "dev-secret")
# ruleid: no-default-session-secret
b = os.environ.get("SESSION_SECRET", "dev-secret")
# ruleid: no-default-session-secret
c = os.getenv("SESSION_SECRET") or "dev-secret"
# ruleid: no-default-session-secret
d = os.environ.get("SESSION_SECRET") or "dev-secret"
# ok: no-default-session-secret
e = os.environ.get("SESSION_SECRET")
# ok: no-default-session-secret
f = os.environ["SESSION_SECRET"]
# ok: no-default-session-secret
g = os.environ.get("OTHER_NAME", "x")
# ok: no-default-session-secret
h = os.environ.get("SESSION_SECRET") or ""
