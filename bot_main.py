# validator_integration.py
import os
import glob
import subprocess
import re

# Desactiva que el bot muestre bloques de "Script corregido"
ALLOW_AUTOFIX = False

# Ruta por defecto de la policy (puedes sobreescribir con la variable de entorno POLICY_PATH)
POLICY_PATH = os.getenv("POLICY_PATH", "policies/policy_oracle.json")

def validate_sql_locally(policy_path: str | None = None) -> str:
    """Ejecuta el validador localmente contra todos los .sql/.pkb/.pks/.pls/.txt versionados."""
    policy = policy_path or POLICY_PATH

    files = [
        f for f in glob.glob("**/*", recursive=True)
        if f.lower().endswith((".sql", ".pkb", ".pks", ".pls", ".txt"))
    ]

    if not os.path.isfile(policy):
        return f"⚠️ Policy no encontrada: {policy}"

    if not files:
        return "✅ No hay archivos .sql/.pkb/.pks/.pls/.txt a validar."

    cmd = ["python", "validator/src/validator.py", policy, *files]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        out = (res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")
        status = "✅ OK" if res.returncode == 0 else f"❌ Falló (exit={res.returncode})"
        return f"{status}\n\n{out.strip()}"
    except Exception as e:
        return f"❌ Error ejecutando validador: {e}"

def _sanitize(output: str) -> str:
    """Quita el bloque de 'Script corregido...' si ALLOW_AUTOFIX=False."""
    if ALLOW_AUTOFIX:
        return output
    return re.sub(r"(?is)script\s+corregido.*", "", output).strip()

def handle_message(_message_text: str = "") -> str:
    """Puerta sencilla para que tu bot llame la validación."""
    raw = validate_sql_locally()
    return _sanitize(raw) or "Validación ejecutada."
