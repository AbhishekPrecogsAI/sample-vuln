
# --- VULN 3: Path traversal with user-controlled file path ---
@app.route("/read-log")
def read_log():
    filename = request.args.get("file", "app.log")
    # PRECOGS_FIX: normalize and restrict filename to prevent path traversal
    safe_name = os.path.normpath(filename)
    # Reject absolute paths or upward traversal
    if os.path.isabs(safe_name) or ".." in safe_name.split(os.sep):
        return {"error": "invalid filename"}, 400
    log_path = os.path.join("logs", safe_name)
    try:
        with open(log_path, "r") as f:
            content = f.read()
        return {"file": filename, "content": content}
    except FileNotFoundError:
        return {"error": "file not found"}, 404
    except PermissionError:
        return {"error": "permission denied"}, 403
    except Exception as e:
        return {"error": str(e)}, 500