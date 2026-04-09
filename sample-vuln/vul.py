
# --- VULN 4: Command injection via os.popen ---
@app.route("/list")
def list_dir():
    path = request.args.get("path", ".")
    # PRECOGS_FIX: avoid invoking a shell; use os.listdir and normalize input to prevent injection
    safe_path = os.path.normpath(path)
    if os.path.isabs(safe_path) or ".." in safe_path.split(os.sep):
        return {"error": "invalid path"}, 400
    full_path = os.path.join(".", safe_path)
    try:
        items = os.listdir(full_path)
        output = "\n".join(items)
        cmd = f"ls -la {full_path}"
        return {"command": cmd, "output": output}
    except FileNotFoundError:
        return {"error": "path not found"}, 404
    except PermissionError:
        return {"error": "permission denied"}, 403
    except Exception as e:
        return {"error": str(e)}, 500