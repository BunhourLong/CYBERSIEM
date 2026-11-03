def handler(request, xff, forwarded_ips, other, raw_forwarded):
    # ruleid: no-leftmost-forwarded-for
    a = request.headers.get("x-forwarded-for")
    # ruleid: no-leftmost-forwarded-for
    b = request.headers.get("X-Forwarded-For", "")
    # ruleid: no-leftmost-forwarded-for
    c = request.headers["X-FORWARDED-FOR"]
    # ruleid: no-leftmost-forwarded-for
    d = raw_forwarded.split(",")[0]
    # ruleid: no-leftmost-forwarded-for
    e = xff.split(",")[0]
    # ruleid: no-leftmost-forwarded-for
    f = forwarded_ips[0]
    # ruleid: no-leftmost-forwarded-for
    g = xff[0]
    # ok: no-leftmost-forwarded-for
    h = request.client.host
    # ok: no-leftmost-forwarded-for
    i = request.headers.get("user-agent")
    # ok: no-leftmost-forwarded-for
    j = other.split(",")[0]
    # ok: no-leftmost-forwarded-for
    k = other[0]
    # ok: no-leftmost-forwarded-for
    return [v.strip() for v in xff.split(",")], a, b, c, d, e, f, g, h, i, j, k
