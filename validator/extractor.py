import os, re, pathlib, base64
try:
    import chardet
except Exception:
    chardet = None
ALLOWED_EXTS = {".sql",".pkb",".pks",".pkg",".ddl",".txt",".prm",".xml",".ps1"}
def _last_ext(name:str) -> str:
    parts = name.lower().strip().split(".")
    return f".{parts[-1]}" if len(parts) > 1 else ""
def _decode_bytes(data:bytes) -> str:
    enc = (chardet.detect(data)["encoding"] if chardet else "utf-8") or "utf-8"
    return data.decode(enc, errors="ignore")
def read_input(message_text=None, attachments=None, raw_urls=None, cli_file=None):
    if cli_file and os.path.exists(cli_file):
        with open(cli_file, "rb") as f:
            return _decode_bytes(f.read())
    if message_text:
        m = re.search(r"```(?:sql|plsql)?\s*(.+?)```", message_text, re.S|re.I)
        if m:
            return m.group(1).strip()
    for a in (attachments or []):
        name = (a.get("filename") or a.get("name") or a.get("title") or "").strip()
        ext  = _last_ext(name)
        if ext in ALLOWED_EXTS or not ext:
            if a.get("path") and os.path.exists(a["path"]):
                with open(a["path"], "rb") as f:
                    return _decode_bytes(f.read())
            if a.get("bytes"):
                return _decode_bytes(a["bytes"])
            if a.get("base64"):
                return _decode_bytes(base64.b64decode(a["base64"]))
            if a.get("content"):
                return str(a["content"])
    if message_text:
        m = re.search(r"([^\n\r]+?\.sql)\b", message_text, re.I)
        if m:
            guess = m.group(1).strip()
            if os.path.exists(guess):
                with open(guess, "rb") as f:
                    return _decode_bytes(f.read())
    raise ValueError("INPUT-NO-CODE")
