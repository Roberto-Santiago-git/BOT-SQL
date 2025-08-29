from validator_integration import handle_mensaje

MAX_SIZE = 500_000  # 500 KB

def validate_sql_bytes(file_bytes: bytes, filename: str) -> str:
    if not file_bytes:
        return "Validator\nVeredicto: SIN-ANÁLISIS [info] INPUT-NO-CODE: sin contenido."
    if len(file_bytes) > MAX_SIZE:
        return "Validator\nVeredicto: SIN-ANÁLISIS [info] INPUT-OVERSIZE: archivo > 500 KB."
    return handle_mensaje(adjunto_bytes=file_bytes, adjunto_nombre=filename)

if __name__ == "__main__":
    import os, sys
    if len(sys.argv) != 2:
        print("Uso: python validator_client.py <ruta.sql>")
        raise SystemExit(2)
    p = sys.argv[1]
    with open(p, "rb") as f:
        data = f.read()
    print(validate_sql_bytes(data, os.path.basename(p)))
