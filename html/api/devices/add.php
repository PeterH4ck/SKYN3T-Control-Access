<?php
/**
 * Archivo: /var/www/html/api/devices/add.php
 * API endpoint para agregar dispositivos
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
    
    // Verificar permisos para gestionar dispositivos
    if (!$auth->hasPermission($user, 'manage_devices') && !$auth->hasPermission($user, 'all')) {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'message' => 'Sin permisos para agregar dispositivos',
            'error_code' => 'INSUFFICIENT_PERMISSIONS'
        ]);
        exit;
    }
    
    // Obtener datos de la petición
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'message' => 'Datos JSON inválidos',
            'error_code' => 'INVALID_JSON'
        ]);
        exit;
    }
    
    // Validar datos requeridos
    $validationRules = [
        'device_name' => ['required' => true, 'max_length' => 100],
        'device_type' => ['required' => true, 'max_length' => 50],
        'mac_address' => ['required' => false, 'regex' => '/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/'],
        'ip_address' => ['required' => false, 'regex' => '/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/'],
        'status' => ['required' => false, 'in' => ['active', 'inactive', 'maintenance']],
        'location' => ['required' => false, 'max_length' => 100],
        'description' => ['required' => false, 'max_length' => 500]
    ];
    
    $validation = validate($input, $validationRules);
    
    if (!$validation['valid']) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'message' => 'Datos de entrada inválidos',
            'errors' => $validation['errors'],
            'error_code' => 'VALIDATION_ERROR'
        ]);
        exit;
    }
    
    $db = Database::getInstance();
    
    // Sanitizar datos
    $deviceName = sanitize($input['device_name']);
    $deviceType = sanitize($input['device_type']);
    $macAddress = isset($input['mac_address']) ? sanitize($input['mac_address']) : null;
    $ipAddress = isset($input['ip_address']) ? sanitize($input['ip_address']) : null;
    $status = isset($input['status']) ? sanitize($input['status']) : 'active';
    $location = isset($input['location']) ? sanitize($input['location']) : null;
    $description = isset($input['description']) ? sanitize($input['description']) : null;
    
    // Verificar que el nombre del dispositivo no esté duplicado
    $existingDevice = $db->fetch("
        SELECT id FROM devices WHERE device_name = ?
    ", [$deviceName]);
    
    if ($existingDevice) {
        http_response_code(409);
        echo json_encode([
            'success' => false,
            'message' => 'Ya existe un dispositivo con ese nombre',
            'error_code' => 'DEVICE_NAME_EXISTS'
        ]);
        exit;
    }
    
    // Verificar que la MAC address no esté duplicada (si se proporciona)
    if ($macAddress) {
        $existingMAC = $db->fetch("
            SELECT id FROM devices WHERE mac_address = ?
        ", [$macAddress]);
        
        if ($existingMAC) {
            http_response_code(409);
            echo json_encode([
                'success' => false,
                'message' => 'Ya existe un dispositivo con esa dirección MAC',
                'error_code' => 'MAC_ADDRESS_EXISTS'
            ]);
            exit;
        }
    }
    
    // Verificar que la IP no esté duplicada (si se proporciona)
    if ($ipAddress) {
        $existingIP = $db->fetch("
            SELECT id FROM devices WHERE ip_address = ?
        ", [$ipAddress]);
        
        if ($existingIP) {
            http_response_code(409);
            echo json_encode([
                'success' => false,
                'message' => 'Ya existe un dispositivo con esa dirección IP',
                'error_code' => 'IP_ADDRESS_EXISTS'
            ]);
            exit;
        }
        
        // Validar formato de IP
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'Dirección IP inválida',
                'error_code' => 'INVALID_IP_FORMAT'
            ]);
            exit;
        }
    }
    
    // Insertar nuevo dispositivo
    $deviceId = $db->insert("
        INSERT INTO devices (
            device_name, device_type, mac_address, ip_address, 
            status, location, description, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ", [
        $deviceName, $deviceType, $macAddress, $ipAddress,
        $status, $location, $description, $user['id']
    ]);
    
    // Obtener el dispositivo creado con información completa
    $newDevice = $db->fetch("
        SELECT d.*, u.username as created_by_username, u.name as created_by_name
        FROM devices d
        LEFT JOIN users u ON d.created_by = u.id
        WHERE d.id = ?
    ", [$deviceId]);
    
    // Formatear respuesta
    $deviceData = [
        'id' => (int)$newDevice['id'],
        'device_name' => $newDevice['device_name'],
        'device_type' => $newDevice['device_type'],
        'mac_address' => $newDevice['mac_address'],
        'ip_address' => $newDevice['ip_address'],
        'status' => $newDevice['status'],
        'location' => $newDevice['location'],
        'description' => $newDevice['description'],
        'created_at' => $newDevice['created_at'],
        'updated_at' => $newDevice['updated_at'],
        'created_by' => [
            'id' => (int)$newDevice['created_by'],
            'username' => $newDevice['created_by_username'],
            'name' => $newDevice['created_by_name']
        ]
    ];
    
    // Log de creación
    Security::logSecurityEvent('device_created', [
        'user_id' => $user['id'],
        'username' => $user['username'],
        'device_id' => $deviceId,
        'device_name' => $deviceName,
        'device_type' => $deviceType,
        'ip_address' => $ipAddress,
        'mac_address' => $macAddress
    ], 'INFO');
    
    // Respuesta exitosa
    http_response_code(201);
    echo json_encode([
        'success' => true,
        'message' => 'Dispositivo creado exitosamente',
        'device' => $deviceData,
        'timestamp' => date('Y-m-d H:i:s')
    ]);
    
} catch (Exception $e) {
    error_log("Error agregando dispositivo: " . $e->getMessage());
    
    // Log del error
    Security::logSecurityEvent('device_add_error', [
        'error' => $e->getMessage(),
        'user_id' => $user['id'] ?? null,
        'input_data' => $input ?? null
    ], 'ERROR');
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Error interno del servidor',
        'error_code' => 'INTERNAL_ERROR'
    ]);
}
?>
