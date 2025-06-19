<?php
/**
 * Archivo: /var/www/html/api/relay/control.php
 * API endpoint para control del relé
 */

// Definir constante del sistema
define('SKYN3T_SYSTEM', true);

// Headers de seguridad y CORS
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Manejo de solicitudes OPTIONS (CORS preflight)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Solo permitir POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'message' => 'Método no permitido',
        'error_code' => 'METHOD_NOT_ALLOWED'
    ]);
    exit;
}

// Incluir sistema de autenticación
require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/database.php';
require_once __DIR__ . '/../../includes/security.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/session.php';

try {
    // Verificar autenticación
    $auth = Auth::getInstance();
    $user = $auth->requireAuth();
    
    if (!$user) {
        exit; // requireAuth ya maneja la respuesta
    }
    
    // Verificar permisos de control de relé
    if (!$auth->hasPermission($user, 'control_relay') && !$auth->hasPermission($user, 'all')) {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'message' => 'Sin permisos para controlar el relé',
            'error_code' => 'INSUFFICIENT_PERMISSIONS'
        ]);
        exit;
    }
    
    // Obtener datos de la petición
    $input = json_decode(file_get_contents('php://input'), true);
    
    // Validar datos requeridos
    if (!isset($input['action'])) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'message' => 'Acción requerida (on/off/toggle)',
            'error_code' => 'MISSING_ACTION'
        ]);
        exit;
    }
    
    $action = strtolower(trim($input['action']));
    $method = $input['method'] ?? 'web'; // web, physical, screen
    
    // Validar acción
    if (!in_array($action, ['on', 'off', 'toggle'])) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'message' => 'Acción inválida. Use: on, off, toggle',
            'error_code' => 'INVALID_ACTION'
        ]);
        exit;
    }
    
    // Validar método
    if (!in_array($method, ['web', 'physical', 'screen'])) {
        $method = 'web';
    }
    
    $db = Database::getInstance();
    
    // Obtener estado actual del relé
    $currentStatus = $db->fetch("
        SELECT relay_state, led_state 
        FROM relay_status 
        ORDER BY timestamp DESC 
        LIMIT 1
    ");
    
    $currentRelayState = $currentStatus ? (bool)$currentStatus['relay_state'] : false;
    $currentLedState = $currentStatus ? (bool)$currentStatus['led_state'] : false;
    
    // Determinar nuevo estado según la acción
    switch ($action) {
        case 'on':
            $newRelayState = true;
            $newLedState = true;
            break;
        case 'off':
            $newRelayState = false;
            $newLedState = false;
            break;
        case 'toggle':
            $newRelayState = !$currentRelayState;
            $newLedState = !$currentLedState;
            break;
    }
    
    // Verificar si hay cambio de estado
    if ($newRelayState === $currentRelayState && $newLedState === $currentLedState) {
        echo json_encode([
            'success' => true,
            'message' => 'El relé ya está en el estado solicitado',
            'relay_state' => $newRelayState,
            'led_state' => $newLedState,
            'changed' => false,
            'previous_state' => $currentRelayState,
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        exit;
    }
    
    // Control físico del relé (usando GPIO)
    $gpioResult = controlPhysicalRelay($newRelayState, $newLedState);
    
    if (!$gpioResult['success']) {
        // Log del error de GPIO
        Security::logSecurityEvent('relay_gpio_error', [
            'user_id' => $user['id'],
            'action' => $action,
            'error' => $gpioResult['message']
        ], 'ERROR');
        
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'message' => 'Error controlando GPIO: ' . $gpioResult['message'],
            'error_code' => 'GPIO_ERROR'
        ]);
        exit;
    }
    
    // Registrar cambio en la base de datos
    $db->executeQuery("
        INSERT INTO relay_status (relay_state, led_state, changed_by, change_method)
        VALUES (?, ?, ?, ?)
    ", [
        $newRelayState ? 1 : 0,
        $newLedState ? 1 : 0,
        $user['id'],
        $method
    ]);
    
    // Log de control exitoso
    Security::logSecurityEvent('relay_controlled', [
        'user_id' => $user['id'],
        'username' => $user['username'],
        'action' => $action,
        'previous_state' => $currentRelayState,
        'new_state' => $newRelayState,
        'method' => $method
    ], 'INFO');
    
    // Respuesta exitosa
    echo json_encode([
        'success' => true,
        'message' => 'Relé controlado exitosamente',
        'action' => $action,
        'relay_state' => $newRelayState,
        'led_state' => $newLedState,
        'changed' => true,
        'previous_state' => $currentRelayState,
        'method' => $method,
        'controlled_by' => [
            'id' => $user['id'],
            'username' => $user['username'],
            'role' => $user['role']
        ],
        'timestamp' => date('Y-m-d H:i:s')
    ]);
    
} catch (Exception $e) {
    error_log("Error en control de relé: " . $e->getMessage());
    
    // Log del error
    Security::logSecurityEvent('relay_control_error', [
        'error' => $e->getMessage(),
        'user_id' => $user['id'] ?? null
    ], 'ERROR');
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Error interno del servidor',
        'error_code' => 'INTERNAL_ERROR'
    ]);
}

/**
 * Controlar relé físico via GPIO
 */
function controlPhysicalRelay($relayState, $ledState) {
    try {
        // Configuración de pines GPIO
        $relayPin = getConfig('RELAY_GPIO_PIN', 23);
        $ledPin = getConfig('LED_GPIO_PIN', 16);
        
        // Valores para GPIO (1 = ON, 0 = OFF)
        $relayValue = $relayState ? 1 : 0;
        $ledValue = $ledState ? 1 : 0;
        
        // Método 1: Usar Python script si existe
        $pythonScript = '/var/www/html/cgi-bin/control-rele.py';
        if (file_exists($pythonScript)) {
            $command = "python3 $pythonScript $relayValue $ledValue 2>&1";
            $output = shell_exec($command);
            
            if (strpos($output, 'ERROR') === false) {
                return [
                    'success' => true,
                    'method' => 'python_script',
                    'output' => trim($output)
                ];
            }
        }
        
        // Método 2: Control directo via sysfs (si está disponible)
        if (is_dir('/sys/class/gpio')) {
            // Exportar pines si no están exportados
            if (!is_dir("/sys/class/gpio/gpio$relayPin")) {
                file_put_contents('/sys/class/gpio/export', $relayPin);
                usleep(100000); // 100ms delay
            }
            
            if (!is_dir("/sys/class/gpio/gpio$ledPin")) {
                file_put_contents('/sys/class/gpio/export', $ledPin);
                usleep(100000);
            }
            
            // Configurar como salida
            file_put_contents("/sys/class/gpio/gpio$relayPin/direction", 'out');
            file_put_contents("/sys/class/gpio/gpio$ledPin/direction", 'out');
            
            // Escribir valores
            file_put_contents("/sys/class/gpio/gpio$relayPin/value", $relayValue);
            file_put_contents("/sys/class/gpio/gpio$ledPin/value", $ledValue);
            
            return [
                'success' => true,
                'method' => 'sysfs_gpio',
                'relay_pin' => $relayPin,
                'led_pin' => $ledPin,
                'relay_value' => $relayValue,
                'led_value' => $ledValue
            ];
        }
        
        // Método 3: Simulación para desarrollo
        if (getConfig('ENVIRONMENT') === 'development' || !is_dir('/sys/class/gpio')) {
            return [
                'success' => true,
                'method' => 'simulation',
                'message' => 'GPIO simulado en modo desarrollo',
                'relay_state' => $relayState,
                'led_state' => $ledState
            ];
        }
        
        return [
            'success' => false,
            'message' => 'No se pudo acceder al GPIO'
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => $e->getMessage()
        ];
    }
}
?>
