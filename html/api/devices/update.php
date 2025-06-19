<?php
/**
 * Archivo: /var/www/html/api/devices/update.php
 * API endpoint para actualizar dispositivos
 */

// Definir constante del sistema
define('SKYN3T_SYSTEM', true);

// Headers de seguridad y CORS
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: PUT, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Manejo de solicitudes OPTIONS (CORS preflight)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Permitir PUT y POST
if (!in_array($_SERVER['REQUEST_METHOD'], ['PUT', 'POST'])) {
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
            'message' => 'Sin permisos para actualizar dispositivos',
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
    
    // Verificar que se proporcione el ID del dispositivo
    if (!isset($input['id'])) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'message' => 'ID del dispositivo requerido',
            'error_code' => 'DEVICE_ID_REQUIRED'
        ]);
        exit;
    }
    
    $deviceId = (int)$input['id'];
    
    $db = Database::getInstance();
    
    // Verificar que el dispositivo existe
    $existingDevice = $db->fetch("
        SELECT * FROM devices WHERE id = ?
    ", [$deviceId]);
    
    if (!$existingDevice) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'message' => 'Dispositivo no encontrado',
            'error_code' => 'DEVICE_NOT_FOUND'
        ]);
        exit;
    }
    
    // Validar datos opcionales
    $validationRules = [
        'device_name' => ['required' => false, 'max_length' => 100],
        'device_type' => ['required' => false, 'max_length' => 50],
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
    
    // Preparar campos a actualizar
    $updateFields = [];
    $params = [];
    $changes = [];
    
    // Verificar y procesar cada campo
    if (isset($input['device_name'])) {
        $deviceName = sanitize($input['device_name']);
        if ($deviceName !== $existingDevice['device_name']) {
            // Verificar que el nuevo nombre no esté duplicado
            $duplicateName = $db->fetch("
                SELECT id FROM devices WHERE device_name = ? AND id != ?
            ", [$deviceName, $deviceId]);
            
            if ($duplicateName) {
                http_response_code(409);
                echo json_encode([
                    'success' => false,
                    'message' => 'Ya existe un dispositivo con ese nombre',
                    'error_code' => 'DEVICE_NAME_EXISTS'
                ]);
                exit;
            }
            
            $updateFields[] = 'device_name = ?';
            $params[] = $deviceName;
            $changes['device_name'] = [
                'from' => $existingDevice['device_name'],
                'to' => $deviceName
            ];
        }
    }
    
    if (isset($input['device_type'])) {
        $deviceType = sanitize($input['device_type']);
        if ($deviceType !== $existingDevice['device_type']) {
            $updateFields[] = 'device_type = ?';
            $params[] = $deviceType;
            $changes['device_type'] = [
                'from' => $existingDevice['device_type'],
                'to' => $deviceType
            ];
        }
    }
    
    if (isset($input['mac_address'])) {
        $macAddress = sanitize($input['mac_address']);
        if ($macAddress !== $existingDevice['mac_address']) {
            // Verificar que la nueva MAC no esté duplicada
            if ($macAddress) {
                $duplicateMAC = $db->fetch("
                    SELECT id FROM devices WHERE mac_address = ? AND id != ?
                ", [$macAddress, $deviceId]);
                
                if ($duplicateMAC) {
                    http_response_code(409);
                    echo json_encode([
                        'success' => false,
                        'message' => 'Ya existe un dispositivo con esa dirección MAC',
                        'error_code' => 'MAC_ADDRESS_EXISTS'
                    ]);
                    exit;
                }
            }
            
            $updateFields[] = 'mac_address = ?';
            $params[] = $macAddress;
            $changes['mac_address'] = [
                'from' => $existingDevice['mac_address'],
                'to' => $macAddress
            ];
        }
    }
    
    if (isset($input['ip_address'])) {
        $ipAddress = sanitize($input['ip_address']);
        if ($ipAddress !== $existingDevice['ip_address']) {
            // Validar formato de IP si no está vacía
            if ($ipAddress && !filter_var($ipAddress, FILTER_VALIDATE_IP)) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'message' => 'Dirección IP inválida',
                    'error_code' => 'INVALID_IP_FORMAT'
                ]);
                exit;
            }
            
            // Verificar que la nueva IP no esté duplicada
            if ($ipAddress) {
                $duplicateIP = $db->fetch("
                    SELECT id FROM devices WHERE ip_address = ? AND id != ?
                ", [$ipAddress, $deviceId]);
                
                if ($duplicateIP) {
                    http_response_code(409);
                    echo json_encode([
                        'success' => false,
                        'message' => 'Ya existe un dispositivo con esa dirección IP',
                        'error_code' => 'IP_ADDRESS_EXISTS'
                    ]);
                    exit;
                }
            }
            
            $updateFields[] = 'ip_address = ?';
            $params[] = $ipAddress;
            $changes['ip_address'] = [
                'from' => $existingDevice['ip_address'],
                'to' => $ipAddress
            ];
        }
    }
    
    if (isset($input['status'])) {
        $status = sanitize($input['status']);
        if ($status !== $existingDevice['status']) {
            $updateFields[] = 'status = ?';
            $params[] = $status;
            $changes['status'] = [
                'from' => $existingDevice['status'],
                'to' => $status
            ];
        }
    }
    
    if (isset($input['location'])) {
        $location = sanitize($input['location']);
        if ($location !== $existingDevice['location']) {
            $updateFields[] = 'location = ?';
            $params[] = $location;
            $changes['location'] = [
                'from' => $existingDevice['location'],
                'to' => $location
            ];
        }
    }
    
    if (isset($input['description'])) {
        $description = sanitize($input['description']);
        if ($description !== $existingDevice['description']) {
            $updateFields[] = 'description = ?';
            $params[] = $description;
            $changes['description'] = [
                'from' => $existingDevice['description'],
                'to' => $description
            ];
        }
    }
    
    // Si no hay cambios, devolver respuesta exitosa sin actualizar
    if (empty($updateFields)) {
        echo json_encode([
            'success' => true,
            'message' => 'No hay cambios para actualizar',
            'device_id' => $deviceId,
            'changes_made' => false,
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        exit;
    }
    
    // Agregar updated_at automático
    $updateFields[] = 'updated_at = NOW()';
    $params[] = $deviceId; // Para WHERE
    
    // Ejecutar actualización
    $sql = "UPDATE devices SET " . implode(', ', $updateFields) . " WHERE id = ?";
    $rowsAffected = $db->update($sql, $params);
    
    if ($rowsAffected === 0) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'message' => 'No se pudo actualizar el dispositivo',
            'error_code' => 'UPDATE_FAILED'
        ]);
        exit;
    }
    
    // Obtener el dispositivo actualizado
    $updatedDevice = $db->fetch("
        SELECT d.*, u.username as created_by_username, u.name as created_by_name
        FROM devices d
        LEFT JOIN users u ON d.created_by = u.id
        WHERE d.id = ?
    ", [$deviceId]);
    
    // Formatear respuesta
    $deviceData = [
        'id' => (int)$updatedDevice['id'],
        'device_name' => $updatedDevice['device_name'],
        'device_type' => $updatedDevice['device_type'],
        'mac_address' => $updatedDevice['mac_address'],
        'ip_address' => $updatedDevice['ip_address'],
        'status' => $updatedDevice['status'],
        'location' => $updatedDevice['location'],
        'description' => $updatedDevice['description'],
        'created_at' => $updatedDevice['created_at'],
        'updated_at' => $updatedDevice['updated_at'],
        'created_by' => [
            'id' => (int)$updatedDevice['created_by'],
            'username' => $updatedDevice['created_by_username'],
            'name' => $updatedDevice['created_by_name']
        ]
    ];
    
    // Log de actualización
    Security::logSecurityEvent('device_updated', [
        'user_id' => $user['id'],
        'username' => $user['username'],
        'device_id' => $deviceId,
        'device_name' => $updatedDevice['device_name'],
        'changes' => $changes
    ], 'INFO');
    
    // Respuesta exitosa
    echo json_encode([
        'success' => true,
        'message' => 'Dispositivo actualizado exitosamente',
        'device' => $deviceData,
        'changes_made' => true,
        'changes' => $changes,
        'timestamp' => date('Y-m-d H:i:s')
    ]);
    
} catch (Exception $e) {
    error_log("Error actualizando dispositivo: " . $e->getMessage());
    
    // Log del error
    Security::logSecurityEvent('device_update_error', [
        'error' => $e->getMessage(),
        'user_id' => $user['id'] ?? null,
        'device_id' => $deviceId ?? null,
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
