#!/usr/bin/env python3
"""
Control de Relé CGI - Versión MySQL
Sistema de Control de Relé
Ubicación: /var/www/html/cgi-bin/control-rele.py
"""

import cgi
import json
import sys
import os
import mysql.connector
from mysql.connector import Error
import RPi.GPIO as GPIO
import time
from datetime import datetime

# Configuración de GPIO
RELAY_PIN = 17
LED_PIN = 27
BUTTON_PIN = 22

# Configuración de base de datos
DB_CONFIG = {
    'host': 'localhost',
    'database': 'relay_control',
    'user': 'relay_app',
    'password': 'relay_app_2025'
}

# Headers CGI
print("Content-Type: application/json")
print("Access-Control-Allow-Origin: *")
print("Access-Control-Allow-Methods: GET, POST")
print("Access-Control-Allow-Headers: Content-Type")
print()

class RelayController:
    def __init__(self):
        self.setup_gpio()
        self.db_connection = None
        
    def setup_gpio(self):
        """Configurar pines GPIO"""
        try:
            GPIO.setmode(GPIO.BCM)
            GPIO.setup(RELAY_PIN, GPIO.OUT)
            GPIO.setup(LED_PIN, GPIO.OUT)
            GPIO.setup(BUTTON_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        except Exception as e:
            self.log_error(f"Error configurando GPIO: {e}")
    
    def get_db_connection(self):
        """Obtener conexión a MySQL"""
        try:
            if not self.db_connection or not self.db_connection.is_connected():
                self.db_connection = mysql.connector.connect(**DB_CONFIG)
            return self.db_connection
        except Error as e:
            self.log_error(f"Error de conexión MySQL: {e}")
            return None
    
    def log_error(self, message):
        """Registrar errores en archivo de log"""
        with open('/var/log/relay_control.log', 'a') as f:
            f.write(f"{datetime.now()}: {message}\n")
    
    def get_current_state(self):
        """Obtener estado actual del relé desde la base de datos"""
        conn = self.get_db_connection()
        if not conn:
            return 'unknown'
        
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT state FROM relay_status ORDER BY timestamp DESC LIMIT 1"
            )
            result = cursor.fetchone()
            cursor.close()
            
            return result['state'] if result else 'off'
        except Error as e:
            self.log_error(f"Error obteniendo estado: {e}")
            return 'unknown'
    
    def save_state(self, state, source='cgi', user_id=None):
        """Guardar estado en la base de datos"""
        conn = self.get_db_connection()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            
            # Obtener IP del cliente
            ip_address = os.environ.get('REMOTE_ADDR', 'unknown')
            
            # Insertar nuevo estado
            cursor.execute(
                """INSERT INTO relay_status (state, source, user_id, ip_address) 
                   VALUES (%s, %s, %s, %s)""",
                (state, source, user_id, ip_address)
            )
            
            # Actualizar configuración del sistema
            cursor.execute(
                """INSERT INTO system_config (`key`, `value`, updated_at) 
                   VALUES ('relay.current_state', %s, NOW())
                   ON DUPLICATE KEY UPDATE value = %s, updated_at = NOW()""",
                (state, state)
            )
            
            # Registrar en log de acceso
            cursor.execute(
                """INSERT INTO access_log (username, action, ip_address, resource, method)
                   VALUES (%s, %s, %s, %s, %s)""",
                ('system', f'relay_{state}', ip_address, '/cgi-bin/control-rele.py', 
                 os.environ.get('REQUEST_METHOD', 'GET'))
            )
            
            conn.commit()
            cursor.close()
            return True
            
        except Error as e:
            self.log_error(f"Error guardando estado: {e}")
            conn.rollback()
            return False
    
    def control_relay(self, action):
        """Controlar el relé y LED"""
        try:
            if action == 'on':
                GPIO.output(RELAY_PIN, GPIO.HIGH)
                GPIO.output(LED_PIN, GPIO.HIGH)
                self.save_state('on')
                return {'status': 'success', 'state': 'on'}
                
            elif action == 'off':
                GPIO.output(RELAY_PIN, GPIO.LOW)
                GPIO.output(LED_PIN, GPIO.LOW)
                self.save_state('off')
                return {'status': 'success', 'state': 'off'}
                
            elif action == 'toggle':
                current = self.get_current_state()
                new_state = 'off' if current == 'on' else 'on'
                return self.control_relay(new_state)
                
            elif action == 'pulse':
                # Encender por 500ms
                GPIO.output(RELAY_PIN, GPIO.HIGH)
                GPIO.output(LED_PIN, GPIO.HIGH)
                self.save_state('pulse')
                time.sleep(0.5)
                GPIO.output(RELAY_PIN, GPIO.LOW)
                GPIO.output(LED_PIN, GPIO.LOW)
                self.save_state('off')
                return {'status': 'success', 'state': 'pulse'}
                
            elif action == 'status':
                state = self.get_current_state()
                # Sincronizar estado físico si es necesario
                if state == 'on':
                    GPIO.output(RELAY_PIN, GPIO.HIGH)
                    GPIO.output(LED_PIN, GPIO.HIGH)
                else:
                    GPIO.output(RELAY_PIN, GPIO.LOW)
                    GPIO.output(LED_PIN, GPIO.LOW)
                
                return {'status': 'success', 'state': state}
                
            else:
                return {'status': 'error', 'message': 'Acción no válida'}
                
        except Exception as e:
            self.log_error(f"Error controlando relé: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_system_info(self):
        """Obtener información del sistema"""
        conn = self.get_db_connection()
        if not conn:
            return {}
        
        try:
            cursor = conn.cursor(dictionary=True)
            
            # Estado actual
            info = {'state': self.get_current_state()}
            
            # Estadísticas de uso
            cursor.execute(
                """SELECT 
                    COUNT(*) as total_changes,
                    COUNT(CASE WHEN state = 'on' THEN 1 END) as on_count,
                    COUNT(CASE WHEN state = 'off' THEN 1 END) as off_count,
                    MIN(timestamp) as first_change,
                    MAX(timestamp) as last_change
                   FROM relay_status
                   WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"""
            )
            stats = cursor.fetchone()
            info['stats_24h'] = stats
            
            # Dispositivos conectados
            cursor.execute(
                "SELECT COUNT(*) as online FROM device_list WHERE status = 'online'"
            )
            devices = cursor.fetchone()
            info['devices_online'] = devices['online']
            
            cursor.close()
            return info
            
        except Error as e:
            self.log_error(f"Error obteniendo info del sistema: {e}")
            return {}
    
    def cleanup(self):
        """Limpiar recursos"""
        if self.db_connection and self.db_connection.is_connected():
            self.db_connection.close()
        # No limpiar GPIO aquí para mantener el estado

def main():
    """Función principal CGI"""
    controller = RelayController()
    
    try:
        # Parsear parámetros
        form = cgi.FieldStorage()
        action = form.getvalue('action', 'status')
        
        # Verificar método HTTP para acciones de cambio
        if action in ['on', 'off', 'toggle', 'pulse'] and os.environ.get('REQUEST_METHOD') != 'POST':
            response = {
                'status': 'error',
                'message': 'Use POST method for control actions'
            }
        else:
            # Ejecutar acción
            if action == 'info':
                response = controller.get_system_info()
            else:
                response = controller.control_relay(action)
        
        # Enviar respuesta JSON
        print(json.dumps(response, indent=2))
        
    except Exception as e:
        error_response = {
            'status': 'error',
            'message': f'Error del sistema: {str(e)}'
        }
        print(json.dumps(error_response))
        controller.log_error(f"Error en main: {e}")
    
    finally:
        controller.cleanup()

if __name__ == "__main__":
    main()