
# --- VULN 5: SSRF (Server-Side Request Forgery) style pattern ---
@app.route("/fetch-url")
def fetch_url():
    url = request.args.get("url", "http://example.com")
    # PRECOGS_FIX: validate scheme and resolve host to prevent SSRF to private/internal addresses
    from urllib.parse import urlparse
    import ipaddress
    import socket

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"error": "invalid url"}, 400
    try:
        ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return {"error": "refused to fetch internal address"}, 403
    except Exception:
        return {"error": "unable to resolve host"}, 400

    try:
        r = requests.get(url, timeout=5)
        return {"status_code": r.status_code, "content": r.text[:200]}
    except requests.RequestException as e:
        return {"error": str(e)}, 502