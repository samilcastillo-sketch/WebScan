"""
scanner.py
Lógica de análisis de seguridad web.
Cada función revisa un aspecto distinto de la página y devuelve
un diccionario estandarizado: {nombre, estado, detalle, riesgo}
"""

import requests
import ssl
import socket
from urllib.parse import urlparse, urljoin
from datetime import datetime
from bs4 import BeautifulSoup


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


def revisar_csrf(html: str) -> dict:
    """Busca formularios y verifica si tienen algún token anti-CSRF visible."""
    try:
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            return {
                "nombre": "Protección CSRF",
                "estado": "info",
                "detalle": "No se encontraron formularios en la página principal.",
                "riesgo": "N/A",
                "explicacion": "No aplica.",
            }

        # Palabras clave comunes en nombres de campos/tokens anti-CSRF
        patrones_csrf = ["csrf", "token", "_token", "authenticity_token", "nonce"]

        forms_sin_proteccion = 0
        for form in forms:
            inputs = form.find_all("input")
            tiene_token = any(
                inp.get("name") and any(p in inp.get("name").lower() for p in patrones_csrf)
                for inp in inputs
            )
            if not tiene_token:
                forms_sin_proteccion += 1

        if forms_sin_proteccion == 0:
            return {
                "nombre": "Protección CSRF",
                "estado": "ok",
                "detalle": f"Los {len(forms)} formulario(s) detectado(s) incluyen un campo tipo token.",
                "riesgo": "N/A",
                "explicacion": "Un token anti-CSRF dificulta que un atacante envíe formularios en nombre del usuario.",
            }
        else:
            return {
                "nombre": "Protección CSRF",
                "estado": "falla",
                "detalle": f"{forms_sin_proteccion} de {len(forms)} formulario(s) sin campo token visible.",
                "riesgo": "Medio",
                "explicacion": "Sin token CSRF, un atacante podría enviar peticiones falsas en nombre del usuario autenticado. Nota: el token también puede enviarse por header o cookie, esto es una detección superficial basada en HTML.",
            }
    except Exception as e:
        return {
            "nombre": "Protección CSRF",
            "estado": "info",
            "detalle": f"No se pudo analizar el HTML: {str(e)}",
            "riesgo": "N/A",
            "explicacion": "No aplica.",
        }


def revisar_tls_version(hostname: str) -> dict:
    """Verifica si el servidor acepta versiones antiguas e inseguras de TLS."""
    versiones_inseguras = {
        "TLSv1": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    }
    detectadas = []

    for nombre_version, version in versiones_inseguras.items():
        try:
            contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            contexto.minimum_version = version
            contexto.maximum_version = version
            contexto.check_hostname = False
            contexto.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with contexto.wrap_socket(sock, server_hostname=hostname):
                    detectadas.append(nombre_version)
        except Exception:
            pass  # Si falla la conexión, esa versión no está disponible (correcto/seguro)

    if detectadas:
        return {
            "nombre": "Versiones TLS obsoletas",
            "estado": "falla",
            "detalle": f"El servidor acepta: {', '.join(detectadas)}",
            "riesgo": "Alto",
            "explicacion": "TLS 1.0 y 1.1 tienen vulnerabilidades conocidas (ej. BEAST, POODLE) y están deprecados desde 2021.",
        }
    else:
        return {
            "nombre": "Versiones TLS obsoletas",
            "estado": "ok",
            "detalle": "No se detectaron versiones TLS obsoletas (1.0/1.1) habilitadas.",
            "riesgo": "N/A",
            "explicacion": "El servidor exige versiones modernas de TLS (1.2+).",
        }


def revisar_info_servidor(headers: dict) -> dict:
    """Revisa si el servidor expone información de versión en headers."""
    headers_riesgosos = ["Server", "X-Powered-By", "X-AspNet-Version"]
    expuestos = []

    for h in headers_riesgosos:
        valor = headers.get(h)
        if valor:
            expuestos.append(f"{h}: {valor}")

    if expuestos:
        return {
            "nombre": "Exposición de tecnología/versión",
            "estado": "alerta",
            "detalle": "; ".join(expuestos),
            "riesgo": "Bajo",
            "explicacion": "Exponer versiones exactas de software facilita a un atacante buscar exploits conocidos para esa versión específica.",
        }
    else:
        return {
            "nombre": "Exposición de tecnología/versión",
            "estado": "ok",
            "detalle": "No se exponen headers con información de versión del servidor.",
            "riesgo": "N/A",
            "explicacion": "Buena práctica: el servidor no revela qué software/versión está usando.",
        }


def revisar_archivos_sensibles(url_base: str) -> list:
    """Verifica si rutas comunes sensibles están expuestas públicamente."""
    rutas_sensibles = [".env", ".git/config", "wp-config.php.bak", "backup.zip", ".DS_Store"]
    resultados = []

    for ruta in rutas_sensibles:
        url_completa = urljoin(url_base, ruta)
        try:
            resp = requests.get(url_completa, timeout=4, allow_redirects=False)
            if resp.status_code == 200:
                resultados.append({
                    "nombre": f"Archivo expuesto: {ruta}",
                    "estado": "falla",
                    "detalle": f"Accesible públicamente (HTTP {resp.status_code})",
                    "riesgo": "Alto",
                    "explicacion": "Este archivo puede contener credenciales, configuración interna o código fuente sensible.",
                })
        except requests.exceptions.RequestException:
            pass  # Si falla la conexión, simplemente no lo reportamos (no es necesariamente bueno ni malo)

    if not resultados:
        return [{
            "nombre": "Archivos sensibles comunes",
            "estado": "ok",
            "detalle": f"Ninguna de las {len(rutas_sensibles)} rutas comunes revisadas está expuesta.",
            "riesgo": "N/A",
            "explicacion": "Buena práctica: no se encontraron archivos de configuración o backups accesibles.",
        }]
    return resultados


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
    resultados.append(revisar_info_servidor(response.headers))
    resultados.append(revisar_csrf(response.text))
    resultados.extend(revisar_archivos_sensibles(url))

    if parsed.scheme == "https":
        resultados.append(revisar_ssl(hostname))
        resultados.append(revisar_tls_version(hostname))
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
