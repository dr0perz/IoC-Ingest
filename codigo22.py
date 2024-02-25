from flask import Flask, render_template, request, redirect, url_for, g, jsonify # Modulos  para trabajar con la herramienta
from urllib.parse import quote_plus # Codifica caracteres especiales en una cadena para que puedan ser utilizados en URLs
from dotenv import load_dotenv #Carga variables de entorno desde un archivo .env
import subprocess # Permite ejecutar comandos del sistema operativo
import re # Permite operaciones con expresiones regulares
import datetime # Permite trabajar con fechas y horas
import sqlite3 # Permite la creación, conexión y ejecución de consultas SQLite
import os # Permite ejecutar comandos del sistema operativo
import requests  # Agregamos el módulo requests para realizar solicitudes HTTP
import json # Facilita la serialización y deserialización de datos JSON en Python

app = Flask(__name__)
load_dotenv()  # Cargar variables de entorno desde .env

# Obtener la API key desde las variables de entorno
api_key = os.getenv("API_KEY")

# Obtener la API key de VirusTotal desde las variables de entorno
virustotal_api_key = os.getenv("VT_API_KEY")

# Configuración de la base de datos SQLite
DATABASE = 'object_names.db'

def connect_db(): # Conexion a la base de datos
    return sqlite3.connect(DATABASE)

def init_db(): # Inicializacion de la base de datos
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def get_db(): # Obtiene la conexion a la base de datos usando 'g' de Flask para almacenar y reutilizar la conexion
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db

@app.teardown_appcontext # Cierre de la conexion de la base de datos
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

def generate_object_name(): # Logica para la generacion de nombres de objetos usados para Palo Alto y almacenarlos en la base de datos
    now = datetime.datetime.now()
    date_str = now.strftime("%d%m%Y")

    db = get_db()

    # Verificar si ya hemos creado objetos hoy y obtener el recuento actual
    count = db.execute('SELECT COUNT(*) FROM object_names WHERE strftime("%Y-%m-%d", created_at) = ?', (now.strftime("%Y-%m-%d"),)).fetchone()[0]

    # Construir el nombre del objeto con sufijo
    obj_name = f"H_EXT_IOC_{date_str}_{count + 1}"

    # Insertar el nombre generado en la base de datos
    db.execute('INSERT INTO object_names (name) VALUES (?)', (obj_name,))
    db.commit()

    return obj_name

# Logica llamada API Palo Alto
def execute_palo_alto_command(action, xpath, element):
    url = f'https://10.250.1.6/api/?type=config&action={action}&xpath={xpath}&element={element}&key={api_key}'
    response = requests.get(url, verify=False)  # Deshabilitamos la verificación del certificado SSL

    if response.status_code != 200:
        # Mensaje de error si falla la solicitud
        print(f'Error en la solicitud: {response.text}')

    return response.text  # Devolver la respuesta del servidor

def extract_date_from_object_name(obj_name): # Funcion para extraer la fecha del nombre de objeto creado
    match = re.match(r'H_EXT_IOC_(\d{2})(\d{2})(\d{4})_', obj_name)
    if match:
        day, month, year = match.groups()
        return datetime.date(int(year), int(month), int(day))
    return None

# Logica llamada API EDR Kaspersky
def add_objects_to_kaspersky(objects, description):
    kaspersky_url = "https://10.1.10.163:443/kata/response_api/v1/00505693b392/settings?sensor_id=all&settings_type=prevention"
    kaspersky_cert_path = "/home/administrator/CertKata/server-cert.pem"
    kaspersky_key_path = "/home/administrator/CertKata/server-key.pem"

    # Recoger todas las prevention rules actuales
    response = requests.get(kaspersky_url, cert=(kaspersky_cert_path, kaspersky_key_path), verify=False)
    existing_rules = response.json().get("response", {}).get("settings", {}).get("objects", [])

    # Añadir nuevos objetos a la lista existente
    updated_rules = existing_rules + objects

    # Construir el cuerpo del JSON para la nueva llamada API
    kaspersky_payload = {
        "settings": {
            "objects": updated_rules
        }
    }

    # Realizar la llamada POST a la API de Kaspersky
    response = requests.post(
        kaspersky_url,
        cert=(kaspersky_cert_path, kaspersky_key_path),
        headers={"Content-Type": "application/json"},
        json=kaspersky_payload,
        verify=False
    )

    # Mensaje de error si falla la solicitud
    if response.status_code != 200:
        print(f'Error en la llamada a la API de Kaspersky: {response.text}')

def get_existing_prevention_rules():
    # Llamada a la API para obtener las prevention rules existentes
    api_url = "https://10.1.10.163:443/kata/response_api/v1/00505693b392/settings?sensor_id=all&settings_type=prevention"
    response = requests.get(api_url, verify=False, cert=('/home/administrator/CertKata/server-cert.pem', '/home/administrator/CertKata/server-key.pem'))
    
    # Parsear la respuesta JSON
    try:
        existing_rules_data = response.json()
        existing_prevention_rules = existing_rules_data.get("settings", {}).get("objects", [])
        return existing_prevention_rules
    except json.JSONDecodeError as e:
        print(f"Error al decodificar la respuesta JSON: {e}")
        return []


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add_objects', methods=['POST'])
def add_objects():
    objects_input = request.form.get('objects')
    description = request.form.get('description', '')  # Obtener la descripción (puede estar vacía)

    # Codificar la descripción para incluir espacios u otros caracteres especiales en la URL
    encoded_description = quote_plus(description)

    # Lista para almacenar los nombres de los objetos generados para Palo Alto
    generated_object_names_palo_alto = []

    # Separar los valores por coma
    input_values = [value.strip() for value in objects_input.split(',')]

    # Lista para almacenar objetos para Kaspersky
    kaspersky_objects = []

    # Obtener las prevention rules existentes
    existing_prevention_rules = get_existing_prevention_rules()

    # Añadir prevention rules existentes a la lista de Kaspersky
    kaspersky_objects.extend(existing_prevention_rules)

    for obj in input_values:
        obj_name_palo_alto = generate_object_name()
        generated_object_names_palo_alto.append(obj_name_palo_alto)  # Guardar el nombre generado para Palo Alto

        if '/' in obj or '-' in obj or re.match(r'^\d+\.\d+\.\d+\.\d+$', obj):
            # IP para Palo Alto
            xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{obj_name_palo_alto}']"
            element = f"<ip-netmask>{obj}</ip-netmask><description>{encoded_description}</description>"
            execute_palo_alto_command('set', xpath, element)

            # También ejecutar el comando para rango de IPs para Palo Alto
            xpath_ip_range = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{obj_name_palo_alto}']"
            element_ip_range = f"<ip-range>{obj}</ip-range><description>{encoded_description}</description>"
            execute_palo_alto_command('set', xpath_ip_range, element_ip_range)

        elif re.match(r'^[a-fA-F0-9]{32}$', obj) or re.match(r'^[a-fA-F0-9]{64}$', obj):
            # MD5 or SHA256 para EDR Kaspersky
            # Añadir a la lista de objetos para Kaspersky
            kaspersky_objects.append(
                {"file": {"md5": obj, "name": description}} if len(obj) == 32 else {"file": {"sha256": obj, "name": description}}
            )
        else:
            # FQDN para Palo Alto
            xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{obj_name_palo_alto}']"
            element = f"<fqdn>{obj}</fqdn><description>{encoded_description}</description>"
            execute_palo_alto_command('set', xpath, element)

    # Añadir objetos a Kaspersky
    add_objects_to_kaspersky(kaspersky_objects, description)

    # Agregar objetos al grupo G_EXT_FRAN para Palo Alto
    xpath_group = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='G_EXT_FRAN']"
    for obj_name_palo_alto in generated_object_names_palo_alto:
        element_group = f"<static><member>{obj_name_palo_alto}</member></static>"
        execute_palo_alto_command('set', xpath_group, element_group)

    return redirect(url_for('index'))

@app.route('/apply_changes', methods=['POST'])
def apply_changes():
    # Aplicar cambios en Palo Alto
    command = f'curl -k --location "https://10.250.1.6//api/?type=commit&action=partial&cmd=%3Ccommit%3E%3Cpartial%3E%3Cadmin%3E%3Cmember%3Etest_api%3C%2Fmember%3E%3C%2Fadmin%3E%3C%2Fpartial%3E%3C%2Fcommit%3E&key={api_key}"'
    subprocess.run(command, shell=True)

    return redirect(url_for('index'))

@app.route('/delete_old_objects', methods=['POST'])
def delete_old_objects():
    # Obtener objetos antiguos de la base de datos
    now = datetime.datetime.now()
    target_date = now - datetime.timedelta(days=90)

    db = get_db()
    old_objects = [row[0] for row in db.execute('SELECT name FROM object_names').fetchall()]

    for obj_name in old_objects:
        # Extraer la fecha del nombre del objeto
        obj_date = extract_date_from_object_name(obj_name)

        if obj_date and obj_date < target_date.date():
            # Eliminar del grupo G_EXT_FRAN
            xpath_group = f"/config/devices/entry/vsys/entry[@name='vsys1']/address-group/entry[@name='G_EXT_FRAN']/static/member[text()='{obj_name}']"
            execute_palo_alto_command('delete', xpath_group, '')

            # Eliminar de Palo Alto
            xpath_delete = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{obj_name}']"
            execute_palo_alto_command('delete', xpath_delete, '')

            # Eliminar de la base de datos SQLite
            db.execute('DELETE FROM object_names WHERE name = ?', (obj_name,))
            db.commit()

    return redirect(url_for('index'))

# Nueva ruta para obtener información de VirusTotal
@app.route('/get_virustotal_info', methods=['POST'])
def get_virustotal_info():
    # Obtener el valor (puede ser IP, dominio, SHA256 o MD5) del formulario
    input_value = request.form.get('ip_address')

    # Determinar si la entrada es una dirección IP, dominio, SHA256 o MD5
    is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+$', input_value) is not None
    is_sha256 = re.match(r'^[a-fA-F0-9]{64}$', input_value) is not None
    is_md5 = re.match(r'^[a-fA-F0-9]{32}$', input_value) is not None

    # Construir la URL de la API de VirusTotal según el tipo de entrada
    if is_ip:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{input_value}'
    elif is_sha256 or is_md5:
        url = f'https://www.virustotal.com/api/v3/files/{input_value}'
    else:
        url = f'https://www.virustotal.com/api/v3/domains/{input_value}'

    # Encabezado con la clave de la API de VirusTotal
    headers = {'x-apikey': virustotal_api_key}

    # Parámetros para solicitar solo los campos deseados
    params = {'fields': 'as_owner,reputation,country,last_analysis_stats,last_analysis_results'}

    # Realizar la solicitud a la API de VirusTotal
    response = requests.get(url, headers=headers, params=params)

    # Verificar si la solicitud fue exitosa
    if response.status_code == 200:
        # Obtener los datos de la respuesta en formato JSON
        data = response.json()

        # Extraer los campos específicos que se mostrarán en el frontend
        as_owner = data.get('data', {}).get('attributes', {}).get('as_owner', '')
        reputation = data.get('data', {}).get('attributes', {}).get('reputation', '')
        country = data.get('data', {}).get('attributes', {}).get('country', '')

        # Obtener el país dependiendo del tipo de entrada
        if is_ip:
            country = data.get('data', {}).get('attributes', {}).get('country', '')
        elif is_sha256 or is_md5:
            # Obtener el valor de "organizations" para MD5 o SHA256
            organizations_info = data.get('data', {}).get('attributes', {}).get('monitor_info', {}).get('organizations', [])
            as_owner = ', '.join(organizations_info) if organizations_info else ''
            country = ''  # Lo dejamos vacio
        else:  # Si es un dominio, obtener el valor de "Admin Country" y "Admin Organization"
            whois_info = data.get('data', {}).get('attributes', {}).get('whois', '')
            match = re.search(r'Admin Country:\s*(.*)', whois_info)
            country = match.group(1) if match else ''

            match_owner = re.search(r'Admin Organization:\s*(.*)', whois_info)
            as_owner = match_owner.group(1) if match_owner else ''

        # Extraer last_analysis_stats y last_analysis_results
        last_analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        last_analysis_results = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})

        # Obtener el nombre de los motores de búsqueda maliciosos
        malicious_engines = [
            engine for engine, result in last_analysis_results.items() if result.get('category') == 'malicious'
        ]

        # Poner en negrita la dirección IP, el dominio, o el hash
        formatted_input = f"{'' if is_ip else 'Direccion IP' if is_ip else 'Dominio' if not is_sha256 and not is_md5 else 'SHA256/MD5'} <strong>'{input_value}'</strong> a analizar"

        # Crear un string formateado con los datos
        result = (
            f"{formatted_input}\n\n"
            f"Propietario: {as_owner}\n"
            f"Pais: {country}\n\n"
            "ANÁLISIS:\n"
            f"\tInofensivo: {last_analysis_stats.get('harmless', 0)}\n"
            f"\tMalicioso: {last_analysis_stats.get('malicious', 0)} ({', '.join(malicious_engines)})\n"
            f"\tSospechoso: {last_analysis_stats.get('suspicious', 0)}\n"
            f"\tTimeout: {last_analysis_stats.get('timeout', 0)}\n"
            f"\tNo detectado: {last_analysis_stats.get('undetected', 0)}\n\n"
            f"REPUTACIÓN: <span style='color: {'red' if reputation < 0 else 'inherit'}; font-weight: {'bold' if reputation < 0 else 'normal'};'>{reputation}</span>\n"
        )
        # Reemplazar "\n" con "<br>" para que los saltos de línea se reflejen en HTML
        result_html = result.replace("\n", "<br>")

        # Devolver el texto formateado al frontend
        return result_html
    else:
        # Si hay un error, devolver un mensaje de error al frontend
        return 'Error al obtener información de VirusTotal'

if __name__ == '__main__':
    # Asegurarse de tener los archivos cert.pem y key.pem en la misma carpeta
    cert_file = 'cert.pem'
    key_file = 'key.pem'

    # Ejecutar la aplicación Flask con soporte HTTPS
    app.run(ssl_context=(cert_file, key_file), host='10.1.1.130', port=5000, debug=True)
