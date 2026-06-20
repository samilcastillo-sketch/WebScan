"""
scanner.py
Lógica de análisis de seguridad web.
Cada función revisa un aspecto distinto de la página y devuelve
un diccionario estandarizado: {nombre, estado, detalle, riesgo}
"""

import requests
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime


# Headers de seguridad que vamos a verificar y por qué importan
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "riesgo": "Alto",
        "explicacion": "Sin HSTS, el navegador puede ser engañado para usar HTTP en vez de HTTPS (downgrade attack)."
    },
    "Content-Security-Policy": {
        "riesgo": "Alto",
        "explicacion": "Sin CSP, el sitio es más vulnerable a ataques XSS (inyección de scripts maliciosos)."
    },
    "X-Frame-Options": {
        "riesgo": "Medio",
        "explicacion": "Sin esto, el sitio puede ser cargado dentro de un iframe malicioso (clickjacking)."
    },
    "X-Content-Type-Options": {
        "riesgo": "Medio",
        "explicacion": "Sin esto, el navegador puede interpretar archivos de forma incorrecta (MIME sniffing)."
    },
    "Referrer-Policy": {
        "riesgo": "Bajo",
        "explicacion": "Sin esto, se puede filtrar información sensible en la URL al navegar a otros sitios."
    },
    "Permissions-Policy": {
        "riesgo": "Bajo",
        "explicacion": "Sin esto, no se restringe el acceso a cámara, micrófono, geolocalización, etc."
    },
}


def normalizar_url(url: str) -> str:
    """Asegura que la URL tenga esquema https:// si no se especifica."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def revisar_headers(headers: dict) -> list:
    """Revisa la presencia de cada header de seguridad importante."""
    resultados = []
    for nombre, info in SECURITY_HEADERS.items():
        presente = nombre in headers
        resultados.append({
            "nombre": nombre,
            "estado": "ok" if presente else "falla",
            "detalle": f"Presente: {headers.get(nombre)}" if presente else "No encontrado",
            "riesgo": info["riesgo"],
            "explicacion": info["explicacion"],
        })
    return resultados


def revisar_cookies(response) -> list:
    """Revisa que las cookies tengan los flags de seguridad correctos."""
    resultados = []
    cookies = response.cookies

    if not cookies:
        return [{
            "nombre": "Cookies",
            "estado": "info",
            "detalle": "El sitio no establece cookies en la respuesta inicial.",
            "riesgo": "N/A",
            "explicacion": "No aplica."
        }]

    for cookie in cookies:
        problemas = []
        if not cookie.secure:
            problemas.append("falta flag Secure")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            problemas.append("falta flag HttpOnly")
        if not cookie.has_nonstandard_attr("SameSite"):
            problemas.append("falta atributo SameSite")

        resultados.append({
            "nombre": f"Cookie: {cookie.name}",
            "estado": "ok" if not problemas else "falla",
            "detalle": "Configuración correcta" if not problemas else ", ".join(problemas),
            "riesgo": "Alto" if problemas else "N/A",
            "explicacion": "Cookies sin estos flags pueden ser robadas vía XSS o interceptadas en redes inseguras.",
        })
    return resultados


def revisar_ssl(hostname: str) -> dict:
    """Revisa validez y expiración del certificado SSL/TLS."""
    try:
        contexto = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with contexto.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                fecha_exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                dias_restantes = (fecha_exp - datetime.utcnow()).days

                if dias_restantes < 0:
                    estado = "falla"
                    detalle = f"Certificado EXPIRADO desde hace {abs(dias_restantes)} días"
                elif dias_restantes < 15:
                    estado = "alerta"
                    detalle = f"Certificado expira en {dias_restantes} días"
                else:
                    estado = "ok"
                    detalle = f"Válido, expira en {dias_restantes} días ({fecha_exp.date()})"

                return {
                    "nombre": "Certificado SSL/TLS",
                    "estado": estado,
                    "detalle": detalle,
                    "riesgo": "Alto" if estado == "falla" else "Bajo",
                    "explicacion": "Un certificado expirado o inválido rompe la confianza y cifrado de la conexión.",
                }
    except Exception as e:
        return {
            "nombre": "Certificado SSL/TLS",
            "estado": "falla",
            "detalle": f"No se pudo verificar: {str(e)}",
            "riesgo": "Alto",
            "explicacion": "No se logró establecer una conexión segura para validar el certificado.",
        }


def calcular_puntaje(resultados: list) -> int:
    """Calcula un puntaje de 0 a 100 según los hallazgos."""
    pesos = {"Alto": 20, "Medio": 10, "Bajo": 5, "N/A": 0}
    penalizacion = 0
    for r in resultados:
        if r["estado"] == "falla":
            penalizacion += pesos.get(r["riesgo"], 5)
    puntaje = max(0, 100 - penalizacion)
    return puntaje


def escanear(url: str) -> dict:
    """Función principal: ejecuta todos los chequeos sobre una URL."""
    url = normalizar_url(url)
    parsed = urlparse(url)
    hostname = parsed.hostname

    try:
        response = requests.get(url, timeout=8, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return {"error": f"No se pudo acceder a la URL: {str(e)}"}

    resultados = []
    resultados.extend(revisar_headers(response.headers))
    resultados.extend(revisar_cookies(response))

    if parsed.scheme == "https":
        resultados.append(revisar_ssl(hostname))
    else:
        resultados.append({
            "nombre": "Conexión HTTPS",
            "estado": "falla",
            "detalle": "El sitio no usa HTTPS",
            "riesgo": "Alto",
            "explicacion": "Sin HTTPS, todo el tráfico viaja sin cifrar y puede ser interceptado.",
        })

    puntaje = calcular_puntaje(resultados)

    return {
        "url": url,
        "puntaje": puntaje,
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "resultados": resultados,
    }
