# validator_integration.py
import os, glob, subprocess, re, tempfile, sys
from pathlib import Path

ALLOW_AUTOFIX = False
DROP_RULES = {"CPPGS-SCHEMA","CPPGS-OWNER","SCHEMA-USE-DEV"}

POLICY_PATH = os.getenv("POLICY_PATH", "policies/policy_oracle.json")
VALIDATOR_SCRIPT = os.getenv("VALIDATOR_SCRIPT", "validator/src/validator.py")
ATTACHMENTS_DIR = os.getenv("ATTACHMENTS_DIR", "/mnt/data")

SUPPORTED_EXT = {".sql",".pkb",".pks",".pls",".txt",".xml",".prm",".ddl",".pkg"}
MAX_SIZE = 500_000  # bytes

def _strip_autofix(text: str) -> str:
    if ALLOW_AUTOFIX: return text
    return re.sub(r"(?is)\n*Script\s+corregido.*\Z", "", text).strip()

def _filter_rule_blocks(text: str) -> str:
    if not DROP_RULES: return text
    lines, keep, skip_next_cita = text.splitlines(), [], False
    for ln in lines:
        if skip_next_cita and ln.strip().lower().startswith(("cita:", "cita :")):
            skip_next_cita = False; continue
        skip_next_cita = False
        rule = None
        m1 = re.search(r"Regla:\s*([A-Z0-9_\-:]+)", ln)
        if m1: rule = m1.group(1)
        else:
            m2 = re.search(r"\[(?:error|warn)\]\s*([A-Z0-9_\-:]+)\s*:", ln, flags=re.I)
            if m2: rule = m2.group(1)
        if rule and rule in DROP_RULES:
            skip_next_cita = True; continue
        keep.append(ln)
    return "\n".join(keep).strip()

def _run_validator(files, policy_path: str | None = None) -> str:
    policy = policy_path or POLICY_PATH
    if not os.path.isfile(policy):
        return f"Validator\nVeredicto: SIN-ANÁLISIS [info] POLICY-NOT-FOUND: {policy}"
    if not os.path.isfile(VALIDATOR_SCRIPT):
        return f"Validator\nVeredicto: SIN-ANÁLISIS [info] ENGINE-NOT-FOUND: {VALIDATOR_SCRIPT}"
    cmd = ["python","-u",VALIDATOR_SCRIPT,policy,*files]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, check=False)
        out = (p.stdout or "") + (("\n"+p.stderr) if p.stderr else "")
        out = _strip_autofix(out)
        out = _filter_rule_blocks(out)
        return out.strip() or "Validator\nVeredicto: SIN-ANÁLISIS [info] ENGINE-NO-OUTPUT"
    except Exception as e:
        return f"Validator\nVeredicto: SIN-ANÁLISIS [info] ENGINE-ERROR: {e}"

def validate_sql_locally(policy_path: str | None = None) -> str:
    files = [f for f in glob.glob("**/*", recursive=True) if Path(f).suffix.lower() in SUPPORTED_EXT]
    if not files:
        return "Validator\nVeredicto: SIN-ANÁLISIS [info] INPUT-NO-FILES: No hay scripts en el repo."
    return _run_validator(files, policy_path)

def _extract_inline(text: str) -> str:
    blocks = re.findall(r"```(?:\w+)?\s*([\s\S]*?)```", text or "", flags=re.MULTILINE)
    blocks = [b.strip() for b in blocks if b.strip()]
    if blocks:
        code = "\n\n".join(blocks)
        return code if len(code) <= MAX_SIZE else ""
    U = (text or "").upper()
    if any(k in U for k in ("CREATE ","ALTER ","INSERT ","DECLARE ","BEGIN ","SELECT ")) and len(U) > 50:
        return text.strip() if len(text) <= MAX_SIZE else ""
    return ""

def _write_temp(code: str, prefer_name: str = "inline.sql") -> str:
    ext = Path(prefer_name).suffix or ".sql"
    with tempfile.NamedTemporaryFile("w", suffix=ext, delete=False, encoding="utf-8") as tf:
        tf.write(code); return tf.name

def _pick_file_by_name(message_text: str) -> str | None:
    if not message_text: return None
    pat = r'[\"\']?([A-Za-z0-9 _\-\.\(\)]+(?:\.sql|\.pkb|\.pks|\.pls|\.txt|\.xml|\.prm|\.ddl|\.pkg))[\"\']?'
    for name in re.findall(pat, message_text, flags=re.I):
        p = Path(ATTACHMENTS_DIR) / name
        if p.exists() and p.is_file() and p.suffix.lower() in SUPPORTED_EXT:
            if p.stat().st_size > MAX_SIZE: return "__OVERSIZE__"
            return str(p)
    return None

def _find_attachment_file() -> str | None:
    d = Path(ATTACHMENTS_DIR)
    if not d.exists(): return None
    candidates = [p for p in d.iterdir() if p.is_file() and p.suffix.lower() in SUPPORTED_EXT]
    if not candidates: return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    path = candidates[0]
    if path.stat().st_size > MAX_SIZE: return "__OVERSIZE__"
    return str(path)

def handle_message(_message_text: str = "", policy_path: str | None = None) -> str:
    """
    Prioridad:
      1) Inline ``` ```
      2) Nombre de archivo escrito en el mensaje
      3) Último adjunto en ATTACHMENTS_DIR
      4) Repo
    Nota: pasa el texto del chat aquí: handle_message(_message_text=incoming_text)
    """
    # 0) override por CLI/env para forzar un archivo
    force = os.getenv("FILE_TO_VALIDATE")
    if not force and len(sys.argv) > 1: force = sys.argv[1]
    if force:
        p = Path(force)
        if not p.exists():
            return f"Validator\nVeredicto: SIN-ANÁLISIS [info] INPUT-NOT-FOUND: {force}"
        if p.suffix.lower() not in SUPPORTED_EXT:
            return "Validator\nVeredicto: SIN-ANÁLISIS [info] INPUT-UNSUPPORTED: extensión no soportada."
        if p.stat().st_size > MAX_SIZE:
            return "Validator\nVeredicto: SIN-ANÁLISIS [info] INPUT-OVERSIZE: archivo > 500 KB."
        return _run_validator([str(p)], policy_path)

    # 1) inline
    code = _extract_inline(_message_text or "")
    if code:
        tmp = _write_temp(code, "inline.sql")
        try: return _run_validator([tmp], policy_path)
        finally:
            try: os.unlink(tmp)
            except: pass

    # 2) por nombre en el mensaje
    named = _pick_file_by_name(_message_text or "")
    if named == "__OVERSIZE__":
        return "Validator\nVeredicto: SIN-ANÁLISIS [info] INPUT-OVERSIZE: archivo > 500 KB."
    if named:
        return _run_validator([named], policy_path)

    # 3) último adjunto
    apath = _find_attachment_file()
    if apath == "__OVERSIZE__":
        return "Validator\nVeredicto: SIN-ANÁLISIS [info] INPUT-OVERSIZE: archivo > 500 KB."
    if apath:
        return _run_validator([apath], policy_path)

    # 4) repo
    return validate_sql_locally(policy_path)

if __name__ == "__main__":
    print(handle_message(_message_text=os.getenv("CHAT_MESSAGE","")))


