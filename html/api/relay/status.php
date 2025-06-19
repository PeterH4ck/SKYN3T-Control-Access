<?php
/**
 * Archivo: /var/www/html/api/relay/status.php
 * API endpoint para obtener estado del relé (MEJORADO)
 */

// Definir constante del sistema
define('SKYN3T_SYSTEM', true);

// Headers de seguridad y CORS
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Manejo de solicitudes OPTIONS (CORS preflight)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Incluir sistema
require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/database.php';
require_once __DIR__ . '/../../includes/security.php';

try {
    // Obtener instancia de base de datos
    $db = Database::getInstance();
    
    // Obtener último estado del relé
    $lastStatus = $db->fetch("
        SELECT relay_state, led_state, changed_by, change_method, timestamp 
        FROM relay_status 
        ORDER BY timestamp DESC 
        LIMIT 1
    ");
    
    if ($lastStatus) {
        // Obtener información del usuario que hizo el último cambio
        $user = null;
        if ($lastStatus['changed_by']) {
            $user = $db->fetch("
                SELECT username, name, role 
                FROM users 
                WHERE id = ?
            ", [$lastStatus['changed_by']]);
        }
        
        // Obtener historial reciente (últimos 10 cambios)
        $history = $db->fetchAll("
            SELECT r.relay_state, r.led_state, r.change_method, r.timestamp,
                   u.username, u.name, u.role
            FROM relay_status r
            LEFT JOIN users u ON r.changed_by = u.id
            ORDER BY r.timestamp DESC
            LIMIT 10
        ");
        
        // Calcular estadísticas
        $stats = $db->fetch("
            SELECT 
                COUNT(*) as total_changes,
                SUM(CASE WHEN relay_state = 1 THEN 1 ELSE 0 END) as times_turned_on,
                SUM(CASE WHEN relay_state = 0 THEN 1 ELSE 0 END) as times_turned_off,
                AVG(CASE WHEN relay_state = 1 THEN 1 ELSE 0 END) * 100 as on_percentage
            FROM relay_status
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        
        // Tiempo desde último cambio
        $lastChangeTime = strtotime($lastStatus['timestamp']);
        $timeSinceChange = time() - $lastChangeTime;
        
        // Formatear tiempo transcurrido
        $timeFormatted = formatTimeElapsed($timeSinceChange);
        
        // Verificar estado físico del GPIO (opcional)
        $physicalStatus = getPhysicalGPIOStatus();
        
        echo json_encode([
            'success' => true,
            'relay_status' => [
                'relay_state' => (bool)$lastStatus['relay_state'],
                'led_state' => (bool)$lastStatus['led_state'],
                'state_text' => $lastStatus['relay_state'] ? 'ON' : 'OFF',
                'last_changed' => $lastStatus['timestamp'],
                'time_since_change' => $timeFormatted,
                'seconds_since_change' => $timeSinceChange,
                'change_method' => $lastStatus['change_method'],
                'changed_by_user' => $user ? [
                    'username' => $user['username'],
                    'name' => $user['name'],
                    'role' => $user['role']
                ] : null
            ],
            'physical_status' => $physicalStatus,
            'statistics_24h' => [
                'total_changes' => (int)$stats['total_changes'],
                'times_turned_on' => (int)$stats['times_turned_on'],
                'times_turned_off' => (int)$stats['times_turned_off'],
                'on_percentage' => round($stats['on_percentage'], 2)
            ],
            'history' => array_map(function($item) {
                return [
                    'relay_state' => (bool)$item['relay_state'],
                    'led_state' => (bool)$item['led_state'],
                    'state_text' => $item['relay_state'] ? 'ON' : 'OFF',
                    'timestamp' => $item['timestamp'],
                    'method' => $item['change_method'],
                    'user' => $item['username'] ? [
                        'username' => $item['username'],
                        'name' => $item['name'],
                        'role' => $item['role']
                    ] : null
                ];
            }, $history),
            'system_status' => 'online',
            'gpio_pins' => [
                'relay_pin' => getConfig('RELAY_GPIO_PIN', 23),
                'led_pin' => getConfig('LED_GPIO_PIN', 16)
            ],
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        
    } else {
        // No hay registros, crear estado inicial
        $db->executeQuery("
            INSERT INTO relay_status (relay_state, led_state, change_method) 
            VALUES (0, 0, 'system')
        ");
        
        echo json_encode([
            'success' => true,
            'relay_status' => [
                'relay_state' => false,
                'led_state' => false,
                'state_text' => 'OFF',
                'last_changed' => date('Y-m-d H:i:s'),
                'time_since_change' => 'Just now',
                'seconds_since_change' => 0,
                'change_method' => 'system',
                'changed_by_user' => null
            ],
            'physical_status' => getPhysicalGPIOStatus(),
            'statistics_24h' => [
                'total_changes' => 0,
                'times_turned_on' => 0,
                'times_turned_off' => 0,
                'on_percentage' => 0
            ],
            'history' => [],
            'system_status' => 'initialized',
            'gpio_pins' => [
                'relay_pin' => getConfig('RELAY_GPIO_PIN', 23),
                'led_pin' => getConfig('LED_GPIO_PIN', 16)
            ],
            'timestamp' => date('Y-m-d H:i:s')
        ]);
    }
    
} catch (Exception $e) {
    error_log("Error obteniendo estado del relé: " . $e->getMessage());
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Error del sistema',
        'error_code' => 'INTERNAL_ERROR',
        'system_status' => 'error',
        'timestamp' => date('Y-m-d H:i:s')
    ]);
}

/**
 * Formatear tiempo transcurrido en formato legible
 */
function formatTimeElapsed($seconds) {
    if ($seconds < 60) {
        return $seconds . ' segundos';
    } elseif ($seconds < 3600) {
        $minutes = floor($seconds / 60);
        return $minutes . ' minuto' . ($minutes > 1 ? 's' : '');
    } elseif ($seconds < 86400) {
        $hours = floor($seconds / 3600);
        return $hours . ' hora' . ($hours > 1 ? 's' : '');
    } else {
        $days = floor($seconds / 86400);
        return $days . ' día' . ($days > 1 ? 's' : '');
    }
}

/**
 * Obtener estado físico real del GPIO
 */
function getPhysicalGPIOStatus() {
    try {
        $relayPin = getConfig('RELAY_GPIO_PIN', 23);
        $ledPin = getConfig('LED_GPIO_PIN', 16);
        
        $status = [
            'available' => false,
            'relay_pin_value' => null,
            'led_pin_value' => null,
            'method' => 'none'
        ];
        
        // Verificar si GPIO está disponible via sysfs
        if (is_dir('/sys/class/gpio')) {
            $status['available'] = true;
            $status['method'] = 'sysfs';
            
            // Leer valor del pin del relé
            if (file_exists("/sys/class/gpio/gpio$relayPin/value")) {
                $relayValue = trim(file_get_contents("/sys/class/gpio/gpio$relayPin/value"));
                $status['relay_pin_value'] = (int)$relayValue;
            }
            
            // Leer valor del pin del LED
            if (file_exists("/sys/class/gpio/gpio$ledPin/value")) {
                $ledValue = trim(file_get_contents("/sys/class/gpio/gpio$ledPin/value"));
                $status['led_pin_value'] = (int)$ledValue;
            }
        }
        
        // Si está en modo desarrollo, simular
        if (getConfig('ENVIRONMENT') === 'development') {
            $status['method'] = 'simulation';
            $status['available'] = true;
        }
        
        return $status;
        
    } catch (Exception $e) {
        return [
            'available' => false,
            'error' => $e->getMessage(),
            'method' => 'error'
        ];
    }
}
?>
