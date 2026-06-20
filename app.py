"""
app.py
Servidor Flask: recibe la URL del usuario, llama al scanner,
guarda el resultado en la base de datos, y permite ver historial
y descargar reportes en PDF.
"""

from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from scanner import escanear
from database import inicializar_db, guardar_escaneo, obtener_historial, obtener_escaneo_por_id, eliminar_escaneo
from reporte_pdf import generar_pdf

app = Flask(__name__)
app.secret_key = "cambia-esta-clave-en-produccion"  # Necesaria solo para mensajes flash

inicializar_db()


@app.route("/", methods=["GET", "POST"])
def index():
    resultado = None
    error = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            resultado = escanear(url)
            if "error" in resultado:
                error = resultado["error"]
                resultado = None
            else:
                escaneo_id = guardar_escaneo(resultado)
                resultado["id"] = escaneo_id
        else:
            error = "Por favor ingresa una URL."

    return render_template("index.html", resultado=resultado, error=error)


@app.route("/historial")
def historial():
    escaneos = obtener_historial(limite=30)
    return render_template("historial.html", escaneos=escaneos)


@app.route("/escaneo/<int:escaneo_id>")
def ver_escaneo(escaneo_id):
    resultado = obtener_escaneo_por_id(escaneo_id)
    if resultado is None:
        flash("Escaneo no encontrado.")
        return redirect(url_for("historial"))
    return render_template("index.html", resultado=resultado, error=None)


@app.route("/escaneo/<int:escaneo_id>/pdf")
def descargar_pdf(escaneo_id):
    resultado = obtener_escaneo_por_id(escaneo_id)
    if resultado is None:
        flash("Escaneo no encontrado.")
        return redirect(url_for("historial"))

    buffer = generar_pdf(resultado)
    nombre_archivo = f"webscan_reporte_{escaneo_id}.pdf"
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=nombre_archivo,
    )


@app.route("/escaneo/<int:escaneo_id>/eliminar", methods=["POST"])
def eliminar(escaneo_id):
    eliminar_escaneo(escaneo_id)
    return redirect(url_for("historial"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
