"""
database.py
Maneja el historial de escaneos en SQLite.
Cada escaneo se guarda como una fila con la URL, fecha, puntaje
y el JSON completo de resultados (para poder regenerar el detalle o el PDF después).
"""

import sqlite3
import json
from datetime import datetime

DB_PATH = "historial.db"


def conectar():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Permite acceder a columnas por nombre
    return conn


def inicializar_db():
    """Crea la tabla de escaneos si no existe. Se llama al arrancar la app."""
    conn = conectar()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS escaneos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            puntaje INTEGER NOT NULL,
            fecha TEXT NOT NULL,
            resultados_json TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def guardar_escaneo(resultado: dict) -> int:
    """Guarda un resultado de escaneo y devuelve el id generado."""
    conn = conectar()
    cursor = conn.execute(
        "INSERT INTO escaneos (url, puntaje, fecha, resultados_json) VALUES (?, ?, ?, ?)",
        (
            resultado["url"],
            resultado["puntaje"],
            resultado["fecha"],
            json.dumps(resultado["resultados"], ensure_ascii=False),
        ),
    )
    conn.commit()
    nuevo_id = cursor.lastrowid
    conn.close()
    return nuevo_id


def obtener_historial(limite: int = 20) -> list:
    """Devuelve los últimos escaneos, del más reciente al más antiguo."""
    conn = conectar()
    filas = conn.execute(
        "SELECT id, url, puntaje, fecha FROM escaneos ORDER BY id DESC LIMIT ?",
        (limite,),
    ).fetchall()
    conn.close()
    return [dict(fila) for fila in filas]


def obtener_escaneo_por_id(escaneo_id: int) -> dict | None:
    """Devuelve un escaneo completo (incluyendo resultados detallados) por su id."""
    conn = conectar()
    fila = conn.execute(
        "SELECT * FROM escaneos WHERE id = ?", (escaneo_id,)
    ).fetchone()
    conn.close()

    if fila is None:
        return None

    return {
        "id": fila["id"],
        "url": fila["url"],
        "puntaje": fila["puntaje"],
        "fecha": fila["fecha"],
        "resultados": json.loads(fila["resultados_json"]),
    }


def eliminar_escaneo(escaneo_id: int) -> bool:
    """Elimina un escaneo del historial."""
    conn = conectar()
    cursor = conn.execute("DELETE FROM escaneos WHERE id = ?", (escaneo_id,))
    conn.commit()
    eliminado = cursor.rowcount > 0
    conn.close()
    return eliminado
