# 🛡️ WebScan — Auditoría Rápida de Seguridad Web

Herramienta web que analiza un sitio y reporta su postura básica de seguridad: headers HTTP, configuración de cookies y validez del certificado SSL/TLS. Construida para practicar conceptos de **ciberseguridad aplicada** junto con **desarrollo web full-stack**.

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-black)
![License](https://img.shields.io/badge/license-MIT-green)

## 📋 ¿Qué hace?

Le das una URL y la herramienta revisa:

- **Headers de seguridad**: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
- **Cookies**: verifica flags `Secure`, `HttpOnly` y `SameSite`
- **Certificado SSL/TLS**: validez y días restantes antes de expirar
- **Versiones TLS obsoletas**: detecta si el servidor aún acepta TLS 1.0/1.1 (inseguros)
- **Protección CSRF**: revisa si los formularios de la página incluyen un token anti-CSRF
- **Exposición de tecnología**: detecta si headers como `Server` o `X-Powered-By` revelan versiones de software
- **Archivos sensibles expuestos**: verifica rutas comunes como `.env`, `.git/config`, backups
- **Puntaje general**: 0-100 según hallazgos, ponderado por nivel de riesgo (Alto/Medio/Bajo)
- **Historial de escaneos**: cada análisis se guarda en SQLite para consultarlo después
- **Reporte en PDF**: descarga un reporte profesional de cualquier escaneo realizado

Cada hallazgo incluye una explicación de **por qué importa**, no solo si pasó o falló — la idea es que sirva como herramienta educativa, no solo como checklist.

## 🎯 Motivación

Este proyecto nace de combinar dos áreas: desarrollo web (Flask, Python) y ciberseguridad (OWASP, hardening de headers HTTP). El objetivo fue aplicar conceptos vistos en cursos de seguridad (Microsoft SC-900, fundamentos de hardening web) en una herramienta funcional, en vez de solo teoría.

## 🛠️ Stack

- **Backend**: Python 3 + Flask
- **Base de datos**: SQLite (historial de escaneos)
- **Generación de PDF**: reportlab
- **Lógica de seguridad**: `requests`, `beautifulsoup4`, módulo `ssl` nativo de Python
- **Frontend**: HTML + CSS (sin frameworks, vanilla)

## 🚀 Instalación y uso

```bash
git clone https://github.com/TU_USUARIO/webscan.git
cd webscan
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Abre `http://localhost:5000` en tu navegador y escanea cualquier URL.

## 📁 Estructura del proyecto

```
webscan/
├── app.py              # Servidor Flask (rutas, formulario, historial, PDF)
├── scanner.py          # Lógica de análisis de seguridad
├── database.py         # Manejo del historial en SQLite
├── reporte_pdf.py       # Generación de reportes PDF
├── requirements.txt    # Dependencias
└── templates/
    ├── index.html       # Interfaz principal del escáner
    └── historial.html    # Listado de escaneos guardados
```

## 🗺️ Roadmap

- [x] Análisis de headers de seguridad
- [x] Verificación de cookies
- [x] Validación de certificado SSL/TLS
- [x] Sistema de puntaje ponderado por riesgo
- [x] Detección de formularios sin protección CSRF
- [x] Detección de versiones TLS obsoletas
- [x] Detección de exposición de tecnología/versión del servidor
- [x] Verificación de archivos sensibles expuestos (.env, .git/config, etc.)
- [x] Historial de escaneos (SQLite)
- [x] Exportar reporte a PDF
- [ ] Dockerización
- [ ] Deploy público

## ⚠️ Uso responsable

Esta herramienta solo hace peticiones HTTP estándar (no intrusivas) a la URL proporcionada — el mismo tipo de petición que haría tu navegador. Aun así, úsala únicamente en sitios de tu propiedad o donde tengas autorización explícita para analizar.

## 📄 Licencia

MIT — libre para usar, modificar y aprender de él.

---

Construido por [Tu Nombre] — estudiante de Ingeniería en Ciberseguridad, UNICARIBE.
