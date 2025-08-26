import os, glob, subprocess

def validate_sql_locally(policy_path="policy_oracle"):
    # Archivos a validar (igual que en el workflow)
    files = [f for f in glob.glob("**/*", recursive=True)
             if f.lower().endswith((".sql", ".pkb", ".pks", ".pls", ".txt"))]

    if not os.path.isfile(policy_path):
        return "⚠️ Policy no encontrada: {}".format(policy_path)

    if not files:
        return "✅ No hay archivos .sql/.pkb/.pks/.pls/.txt a validar."

    cmd = ["python", "validator/src/validator.py", policy_path] + files
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        out = (res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")
        code = "✅ OK" if res.returncode == 0 else "❌ Falló (exit={})".format(res.returncode)
        return "{}\n\n{}".format(code, out.strip())
    except Exception as e:
        return "❌ Error ejecutando validador: {}".format(e)
