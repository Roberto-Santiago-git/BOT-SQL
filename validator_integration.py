# validator_integration.py
import subprocess, os, tempfile
from pathlib import Path

# --- Rutas base ---
ROOT = Path(__file__).resolve().parent

# Permite overrides por variables de entorno
ENV_POLICY = os.environ.get("VALIDATOR_POLICY")
ENV_SCRIPT = os.environ.get("VALIDATOR_SCRIPT")

# Candidatos por orden de preferencia
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
        if not p:
            continue
        pp = Path(p)
        if pp.exists():
            return str(pp)
    # fallback claro aunque no exista
    for p in paths:
        if p:
            return str(p)
    return "validator.py"

def _python_cmd():
    # Prioriza env PYTHON, luego 'py' en Windows, luego python3
    exe = os.environ.get("PYTHON")
    if exe:
        return [exe]
    if os.name == "nt":
        return ["py"]
    return ["python3"]

POLICY = _first_existing(POLICY_CANDIDATES)
SCRIPT = _first_existing(SCRIPT_CANDIDATES)

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
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except subprocess.TimeoutExpired:
        return 99, "", "Tiempo de espera agotado al validar."
    except FileNotFoundError as e:
        return 98, "", f"No se encontró ejecutable o script: {e}"
    except Exception as e:
        return 97, "", f"Fallo al ejecutar validador: {e}"

def validar_sql_por_ruta(ruta_sql: str, timeout=30):
    return _run_validator([ruta_sql], timeout=timeout)

def validar_sql_por_texto(sql_text: str, timeout=30):
    return _run_validator(["-"], input_text=(sql_text or ""), timeout=timeout)

def handle_mensaje(usuario_texto: str = None, adjunto_bytes: bytes = None, adjunto_nombre: str = None):
    # Preflight: verifica existencia de policy/script
    if not Path(POLICY).exists():
        return f"No encuentro la policy en: {POLICY}"
    if not Path(SCRIPT).exists():
        return f"No encuentro el script en: {SCRIPT}"

    if adjunto_bytes is not None:
        ext = (Path(adjunto_nombre or "").suffix or ".sql").lower()
        if ext not in {".sql", ".pkb", ".pks", ".pkg", ".ddl", ".txt"}:
            return "Formato no soportado."
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as f:
                f.write(adjunto_bytes)
                tmp = f.name
            code, out, err = validar_sql_por_ruta(tmp)
        finally:
            if tmp:
                try: os.unlink(tmp)
                except: pass
    else:
        if not (usuario_texto or "").strip():
            return "No recibí SQL ni archivo."
        code, out, err = validar_sql_por_texto(usuario_texto)

    return out if out else (f"Error:\n{err}" if err else "Error desconocido.")
