# validator_integration.py
import os
import re
import tempfile
import subprocess
from pathlib import Path

# --- Config de salida del bot ---
STRIP_AUTOFIX = True                 # quita cualquier bloque "Script corregido..."
DROP_RULES = {"CPPGS-SCHEMA"}        # oculta hallazgos con esos rule_id

# --- Rutas base / descubrimiento ---
ROOT = Path(__file__).resolve().parent
ENV_POLICY = os.environ.get("VALIDATOR_POLICY")
ENV_SCRIPT = os.environ.get("VALIDATOR_SCRIPT")

POLICY_CANDIDATES = [
    ENV_POLICY,
    ROOT / "policy_oracle" / "policy_oracle.json",
    ROOT / "policy_oracle.json",
    ROOT / "policy_ip.json",
]
SCRIPT_CANDIDATES = [
    ENV_SCRIPT,
    ROOT / "validator" / "src" / "validator.py",
    ROOT / "validator.py",
]

def _first_existing(paths):
    for p in paths:
        if p and Path(p).exists():
            return str(p)
    for p in paths:
        if p:
            return str(p)
    return "validator.py"

def _python_cmd():
    exe = os.environ.get("PYTHON")
    if exe:
        return [exe]
    if os.name == "nt":
        return ["py", "-3"]
    return ["python3"]

POLICY = _first_existing(POLICY_CANDIDATES)
SCRIPT = _first_existing(SCRIPT_CANDIDATES)

# --- Post-procesado de salida ---
def _clean_output(text: str) -> str:
    out = text or ""

    # 1) Quitar bloque "Script corregido ..."
    if STRIP_AUTOFIX:
        out = re.sub(r"(?is)\n+Script corregido.*$", "", out).strip()

    # 2) Filtrar bloques por rule_id (línea "  Regla: <ID> — ...")
    if DROP_RULES:
        lines = out.splitlines()
        keep, drop = [], False
        for ln in lines:
            m = re.search(r"Regla:\s*([A-Z0-9_\-:]+)", ln)
            if m and m.group(1) in DROP_RULES:
                drop = True
            if not drop:
                keep.append(ln)
            if ln.strip() == "":          # fin de bloque de hallazgo
                drop = False
        out = "\n".join(keep).strip()

    return out

# --- Ejecución del validador ---
def _run_validator(args, input_text=None, timeout=30):
    cmd = _python_cmd() + [SCRIPT, POLICY] + list(args)
    try:
        p = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=ROOT,
        )
        merged = ((p.stdout or "") + ("\n" + p.stderr if p.stderr else "")).strip()
        return p.returncode, _clean_output(merged)
    except subprocess.TimeoutExpired:
        return 99, "Veredicto: NO CUMPLE\n- [error] Tiempo de espera agotado al validar."
    except FileNotFoundError as e:
        return 98, f"Veredicto: NO CUMPLE\n- [error] No se encontró ejecutable o script: {e}"
    except Exception as e:
        return 97, f"Veredicto: NO CUMPLE\n- [error] Fallo al ejecutar validador: {e}"

# --- APIs para tu bot ---
def validar_sql_por_ruta(ruta_sql: str, timeout=30):
    return _run_validator([ruta_sql], timeout=timeout)

def validar_sql_por_texto(sql_text: str, timeout=30):
    return _run_validator(["-"], input_text=(sql_text or ""), timeout=timeout)

def handle_mensaje(usuario_texto: str = None, adjunto_bytes: bytes = None, adjunto_nombre: str = None):
    if not Path(POLICY).exists():
        return f"Veredicto: NO CUMPLE\n- [error] Policy no encontrada: {POLICY}"
    if not Path(SCRIPT).exists():
        return f"Veredicto: NO CUMPLE\n- [error] Script no encontrado: {SCRIPT}"

    if adjunto_bytes is not None:
        ext = (Path(adjunto_nombre or "").suffix or ".sql").lower()
        if ext not in {".sql", ".pkb", ".pks", ".pkg", ".ddl", ".txt"}:
            return "Veredicto: NO CUMPLE\n- [error] Formato no soportado."
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as f:
                f.write(adjunto_bytes or b"")
                tmp = f.name
            _, out = validar_sql_por_ruta(tmp)
        finally:
            if tmp:
                try: os.unlink(tmp)
                except: pass
        return out

    if (usuario_texto or "").strip():
        _, out = validar_sql_por_texto(usuario_texto)
        return out

    return "Veredicto: NO CUMPLE\n- [error] No recibí SQL ni archivo."
