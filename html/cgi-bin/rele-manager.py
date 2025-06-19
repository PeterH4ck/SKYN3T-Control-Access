#!/usr/bin/python3

import cgi
import cgitb
import RPi.GPIO as GPIO
import time
import json
import os
from datetime import datetime

# Configuración
RELAY_PIN = 23
LED_PIN = 16
LOG_FILE = "/var/www/html/boton_ON-OFF/rele-manager.log"

# Habilitar depuración
cgitb.enable()

# Configuración inicial GPIO
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
GPIO.setup(RELAY_PIN, GPIO.IN)
GPIO.setup(LED_PIN, GPIO.IN)

print("Content-Type: application/json\n")

# Obtener parámetros
form = cgi.FieldStorage()
action = form.getvalue('action')

def log_message(message):
    """Registra mensajes en el archivo de log"""
    try:
        with open(LOG_FILE, 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] {message}\n")
    except:
        pass

response = {'status': 'error', 'message': 'Acción no válida', 'active': False}

try:
    if action == 'start':
        # Habilitar control físico
        log_message("Habilitando control físico del relé")
        response = {'status': 'success', 'message': 'Panel Táctil ACTIVADO', 'active': True}
        
    elif action == 'stop':
        # Deshabilitar control físico
        log_message("Deshabilitando control físico del relé")
        response = {'status': 'success', 'message': 'Panel Táctil DESACTIVADO', 'active': False}
        
    elif action == 'status':
        # Verificar estado del manager (si está habilitado o no)
        try:
            # Leer estado del archivo de configuración o usar default
            response = {'status': 'success', 'message': 'Estado del control físico', 'active': True}
        except:
            response = {'status': 'success', 'message': 'Estado del control físico', 'active': False}
            
    elif action == 'log':
        # Devolver contenido del log
        try:
            with open(LOG_FILE, 'r') as f:
                logs = f.read()
            print("Content-Type: text/plain\n")
            print(logs)
            exit()
        except:
            print("Content-Type: text/plain\n")
            print("No hay registros disponibles")
            exit()

except Exception as e:
    log_message(f"Error: {str(e)}")
    response = {'status': 'error', 'message': str(e), 'active': False}

print(json.dumps(response))
