# network_scanner

Descargo de Responsabilidad

Importante: Todo el código y la estructura de este proyecto fueron generados y refactorizados por el modelo de lenguaje grande Gemini Advanced 2.5 Pro (experimental) de Google, basándose en un script inicial y directivas proporcionadas por el usuario.

Tutorial y Forma de Uso

Este script permite escanear redes para descubrir dispositivos y obtener información sobre ellos.

Prerrequisitos:

Python 3.7+
pip
Nmap instalado en el sistema: (Descargar desde https://nmap.org/download.html)

Instalación:

Clona el repositorio (si está en GitHub) o asegúrate de tener todos los archivos (main.py, el directorio network_scanner/ con sus archivos internos, requirements.txt) en tu máquina local.
Abre una terminal en el directorio raíz del proyecto.
Crea y activa un entorno virtual (recomendado): python -m venv .venv
Linux/macOS:
source .venv/bin/activate
Windows:
..venv\Scripts\activate
Instala las dependencias: pip install -r requirements.txt
Ejecución:

Ejecuta el script main.py desde la terminal. Necesitarás sudo (Linux/macOS) o privilegios de Administrador (Windows) para el escaneo ARP en la red local.

Sintaxis:

[sudo] python main.py [--local CIDR] [--remote CIDR] [--nmap-args "ARGS"] [--skip-local] [--skip-remote]

Ejemplos Comunes:

Escanear red local por defecto (ARP+Nmap detallado):
sudo python main.py

Escanear red local específica y remota con Nmap rápido:
sudo python main.py --local 192.168.50.0/24 --remote 10.10.0.0/16 --nmap-args "-T4 -F"

Solo escanear red local por defecto:
sudo python main.py --skip-remote

Solo hacer ping scan a un rango remoto:
sudo python main.py --remote 8.8.8.0/24 --nmap-args "-sn" --skip-local

Ver todas las opciones:
python main.py --help

Documentación General del Proyecto

El proyecto está diseñado con una estructura modular para facilitar su mantenimiento y extensión:

main.py: Es el punto de entrada principal. Se encarga de procesar los argumentos que le pasas por la línea de comandos, llamar a las funciones de escaneo correspondientes y mostrar el resumen final de los dispositivos encontrados.
network_scanner/ (Paquete Principal): Contiene toda la lógica interna del escáner.
scanner.py: Es el corazón del escáner. Incluye las funciones que realizan el descubrimiento ARP con Scapy y ejecutan los escaneos con Nmap. También contiene la lógica para interpretar los resultados de Nmap y extraer la información relevante (IP, MAC, OS, puertos, etc.).
utils.py: Contiene funciones de utilidad reutilizables, como la que busca el fabricante de la dirección MAC y la clase Spinner que muestra la animación mientras se realizan tareas largas.
models.py: Define la estructura de datos (DeviceInfo) que se utiliza internamente para almacenar la información de cada dispositivo de forma organizada.
init.py: Archivo que le indica a Python que el directorio network_scanner es un paquete importable.
requirements.txt: Archivo que lista las bibliotecas Python externas necesarias para que el proyecto funcione (scapy, python-nmap, mac-vendor-lookup).
Otros archivos (gitignore, LICENSE): Archivos estándar para gestión con Git y definición de la licencia de uso.

Sugerencias para Mejoras Futuras

El proyecto actual es funcional, pero podría seguir mejorándose en varias áreas:

Formatos de Salida: Permitir guardar los resultados en diferentes formatos de archivo, como CSV o JSON, para facilitar el análisis posterior.
Rendimiento: Explorar el uso de programación asíncrona (asyncio) para realizar múltiples escaneos Nmap o procesar resultados de forma concurrente, lo que podría acelerar el proceso en redes grandes.
Interfaz Gráfica (GUI): Desarrollar una interfaz gráfica de usuario simple (con Tkinter, PyQt, etc.) para hacerlo más amigable para usuarios no técnicos.
Pruebas Automatizadas: Añadir pruebas unitarias (con pytest) para asegurar que las diferentes partes del código (especialmente el parseo de resultados y las utilidades) funcionen como se espera y detectar errores al hacer cambios.
Configuración Externa: Permitir definir configuraciones por defecto (rangos comunes, argumentos Nmap preferidos) en un archivo externo (ej. config.yaml).
Empaquetado: Preparar el proyecto para ser instalado como un paquete estándar de Python (pip install .), permitiendo ejecutarlo como un comando desde cualquier lugar.
Manejo de Errores: Hacer el manejo de errores más detallado y robusto, quizás definiendo excepciones personalizadas para diferentes tipos de fallos (permisos, Nmap no encontrado, rango inválido, etc.).
Escaneo UDP: Añadir la opción de realizar escaneos de puertos UDP con Nmap (aunque son más lentos y requieren privilegios).
