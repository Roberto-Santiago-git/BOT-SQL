# validator_integration.py
import os, glob, subprocess, re, tempfile
from pathlib import Path

# === Config ===
ALLOW_AUTOFIX = False  # no mostrar "Script corregido ..."
# Oculta reglas que no quieres que aparezcan en la salida del bot:
DROP_RULES = {
    "CPPGS-SCHEMA",
    "CPPGS-OWNER",
    "SCHEMA-USE-DEV",
}

POLICY_PATH  = os.getenv("POLICY_PATH", "policies/policy_oracle.json")
SCRIPT_PATH  = os.getenv("VALIDATOR_SCRIPT", "validator/src/validator.py")

# === Helpers ===
def _run_validator(policy_path: str, files: list[str]) -> tuple[int, str]:
    """Ejecuta el validador y retorna (exit_code, stdout+stderr)."""
    cmd = ["python", SCRIPT_PATH, policy_path, *files]
    p = subprocess.run(cmd, capture_output=True, text=True, check=False)
    out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
    return p.returncode, out

def _strip_autofix_block(text: str) -> str:
    if ALLOW_AUTOFIX:
        return text
    # quita todo lo que siga a "Script corregido (copiar y pegar):"
    return re.sub(r"(?is)\n+Script\s+corregido.*$", "", text).strip()

def _filter_rule_blocks(text: str) -> str:
    """Quita bloques de hallazgo cuyo 'Regla: <RULE>' esté en DROP_RULES."""
    if not DROP_RULES:
        return text
    lines = text.splitlines()
    keep, skip = [], False
    for ln in lines:
        m = re.search(r"Regla:\s*([A-Z0-9_\-:]+)", ln)
        if m and m.group(1) in DROP_RULES:
            skip = True
        if not skip:
            keep.append(ln)
        if ln.strip() == "":
            skip = False
    return "\n".join(keep).strip()

def _ensure_header(text: str) -> str:
    """Asegura que inicie con 'Validator' (alineado a tus instrucciones)."""
    t = text.lstrip()
    return ("Validator\n" + t) if not t.startswith("Validator") else text

def _sanitize(text: str) -> str:
    text = _strip_autofix_block(text)
    text = _filter_rule_blocks(text)
    text = _ensure_header(text)
    return text.strip()

def _ensure_policy() -> str | None:
    if Path(POLICY_PATH).is_file():
        return POLICY_PATH
    return None

# === API pública ===
def validate_sql_locally(policy_path: str | None = None, files: list[str] | None = None) -> str:
    """Valida repo completo o lista de archivos específica."""
    policy = policy_path or _ensure_policy()
    if not policy:
        return f"Validator\nVeredicto: NO CUMPLE\n[error] POLICY-NOT-FOUND: No se encontró la policy en {POLICY_PATH}"

    if files is None:
        files = [
            f for f in glob.glob("**/*", recursive=True)
            if f.lower().endswith((".sql", ".pkb", ".pks", ".pls", ".txt"))
        ]

    if not files:
        return "Validator\nVeredicto: CUMPLE"

    code, out = _run_validator(policy, files)
    if not out.strip():
        out = f"Veredicto: {'CUMPLE' if code == 0 else 'NO CUMPLE'}"
    return _sanitize(out)

def handle_mensaje(usuario_texto: str | None = None,
                   adjunto_bytes: bytes | None = None,
                   adjunto_nombre: str | None = None,
                   policy_path: str | None = None,
                   files: list[str] | None = None) -> str:
    """
    Uso en el bot:
      - Texto en el mensaje: handle_mensaje(usuario_texto=sql_text)
      - Con adjunto: handle_mensaje(adjunto_bytes=b, adjunto_nombre="archivo.sql")
      - Lista explícita de rutas: handle_mensaje(files=['a.sql','b.sql'])
    """
    policy = policy_path or _ensure_policy()
    if not policy:
        return f"Validator\nVeredicto: NO CUMPLE\n[error] POLICY-NOT-FOUND: No se encontró la policy en {POLICY_PATH}"

    # Prioridad: files explícitos > adjunto > texto > repo completo
    if files:
        return validate_sql_locally(policy_path=policy, files=files)

    tmp_path = None
    try:
        if adjunto_bytes is not None:
            suf = Path(adjunto_nombre or "adjunto.sql").suffix or ".sql"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suf) as tf:
                tf.write(adjunto_bytes)
                tmp_path = tf.name
            return validate_sql_locally(policy_path=policy, files=[tmp_path])

        if (usuario_texto or "").strip():
            with tempfile.NamedTemporaryFile(delete=False, suffix=".sql") as tf:
                tf.write(usuario_texto.encode("utf-8", errors="ignore"))
                tmp_path = tf.name
            return validate_sql_locally(policy_path=policy, files=[tmp_path])

        # Sin insumo: valida repo completo
        return validate_sql_locally(policy_path=policy, files=None)
    finally:
        if tmp_path:
            try: os.unlink(tmp_path)
            except: pass

# Alias para compatibilidad con tu bot actual
def handle_message(_message_text: str = "") -> str:
    """Mantiene compatibilidad: valida repo completo."""
    return validate_sql_locally()

