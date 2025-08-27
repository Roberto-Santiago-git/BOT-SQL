# validator_integration.py
import os, re, tempfile
from pathlib import Path
from subprocess import run

# === CONFIG ===
ALLOW_AUTOFIX = False          # NO imprimir bloque "Script corregido"
DROP_RULES_EXACT = {           # IDs exactos a ocultar (si aparecen)
    "CPPGS-SCHEMA", "CPPGS-OWNER", "CPPGS-LOG-START", "CPPGS-LOG-END",
    "CPPGS-LOG-ERROR", "CPPGS-EXCEPTION", "CPPGS-NAMING", "CPPGS-COMMENT",
}
DROP_RULES_PREFIX = ("CPPGS-",)  # Oculta cualquier regla que inicie con estos prefijos

# === RUTAS ===
ROOT = Path(__file__).resolve().parent
POLICY = os.environ.get("VALIDATOR_POLICY") or str(ROOT / "policy_oracle.json")
SCRIPT = os.environ.get("VALIDATOR_SCRIPT") or str(ROOT / "validator" / "src" / "validator.py")

def _python_cmd():
    return [os.environ.get("PYTHON") or ("py" if os.name == "nt" else "python3")]

def _run_validator(args, input_text=None, timeout=30):
    cmd = _python_cmd() + [SCRIPT, POLICY] + list(args)
    p = run(cmd, input=input_text, capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
    return (p.returncode, out.strip())

def _strip_autofix_and_branding(text: str) -> str:
    # quitar bloque "Script corregido ..." si existiera
    if not ALLOW_AUTOFIX:
        text = re.sub(r"(?is)\n+Script corregido.*$", "", text).strip()
    # quitar cabeceras ajenas como "Validator CyGD"
    text = re.sub(r"(?im)^\s*Validator\s+CyGD\s*$\n?", "", text)
    return text

def _drop_rule_blocks(text: str) -> str:
    """
    El output de tu bot ya viene en forma:
      [error] RULE_ID: descripción
    (bloques separados por una línea en blanco)
    También soporta el formato de nuestro validator:
      Regla: RULE_ID — desc
    """
    lines = text.splitlines()
    kept = []
    skip = False

    for ln in lines:
        # 1) Formato [severity] RULE_ID:
        m = re.match(r"^\s*\[(?:error|warn|warning)\]\s*([A-Z0-9_\-]+)\s*:", ln, flags=re.I)
        # 2) Formato "Regla: RULE_ID — desc"
        r = re.search(r"Regla:\s*([A-Z0-9_\-:]+)", ln)

        rule = None
        if m: rule = m.group(1)
        elif r: rule = r.group(1)

        if rule:
            # decidir si ocultar este bloque
            hide = (rule in DROP_RULES_EXACT) or any(rule.startswith(p) for p in DROP_RULES_PREFIX)
            skip = hide

        if not skip:
            kept.append(ln)

        # fin de bloque: línea en blanco
        if ln.strip() == "":
            skip = False

    return "\n".join(kept).strip()

def handle_mensaje(usuario_texto: str = None, adjunto_bytes: bytes = None, adjunto_nombre: str = None):
    if not Path(POLICY).exists():
        return f"Validator\nVeredicto: NO CUMPLE\n[error] TOOL-NO-POLICY: No encuentro la policy en {POLICY}"
    if not Path(SCRIPT).exists():
        return f"Validator\nVeredicto: NO CUMPLE\n[error] TOOL-NO-SCRIPT: No encuentro el script en {SCRIPT}"

    if adjunto_bytes is not None:
        ext = (Path(adjunto_nombre or "").suffix or ".sql").lower()
        if ext not in {".sql", ".pkb", ".pks", ".pkg", ".ddl", ".txt"}:
            return "Validator\nVeredicto: NO CUMPLE\n[error] INPUT-TYPE: Formato no soportado."
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as f:
            f.write(adjunto_bytes)
            tmp = f.name
        try:
            _, out = _run_validator([tmp])
        finally:
            try: os.unlink(tmp)
            except: pass
    else:
        if not (usuario_texto or "").strip():
            return "Validator\nVeredicto: NO CUMPLE\n[error] INPUT-NO-CODE: No recibí SQL ni archivo."
        _, out = _run_validator(["-"], input_text=usuario_texto)

    out = _strip_autofix_and_branding(out)
    out = _drop_rule_blocks(out)

    # Garantiza encabezado mínimo si el validador solo imprimió el veredicto
    if not out.startswith("Validator"):
        out = "Validator\n" + out
    return out
    # compat: algunos lugares siguen importando handle_message
def handle_message(*args, **kwargs):
    return handle_mensaje(*args, **kwargs)

