"""
app.py
Servidor Flask: recibe la URL del usuario, llama al scanner,
y muestra los resultados.
"""

from flask import Flask, render_template, request
from scanner import escanear

app = Flask(__name__)


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
            error = "Por favor ingresa una URL."

    return render_template("index.html", resultado=resultado, error=error)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
