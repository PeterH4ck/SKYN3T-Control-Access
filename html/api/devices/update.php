// ===========================
// ARCHIVO: /var/www/html/api/devices/update.php (MEJORADO)
// DESCRIPCIÓN: Actualizar dispositivo existente
// ===========================
?>
<?php
require_once '../../includes/config.php';
require_once '../../includes/database.php';
require_once '../../includes/auth.php';
require_once '../../includes/security.php';

// Headers
header('Content-Type: application/json; charset=UTF-8');
cors_headers();

// Solo permitir PUT o POST
if (!in_array($_SERVER['REQUEST_METHOD'], ['PUT', 'POST'])) {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// Verificar autenticación
$auth_result = verify_api_auth();
if (!$auth_result['success']) {
    http_response_code(401);
    echo json_encode(['error' => $auth_result['message']]);
    exit;
}

$user = $auth_result['user'];

// Verificar permisos
if (!in_array($user['role'], ['Admin', 'SuperUser'])) {
    http_response_code(403);
    echo json_encode(['error' => 'Insufficient permissions']);
    exit;
}

// Obtener datos
$input = get_json_input();

// Validar device_id
$device_id = (int)($input['device_id'] ?? 0);
if ($device_id <= 0) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid device ID']);
    exit;
}

try {
    $db = Database::getInstance()->getConnection();
    
    // Verificar que el dispositivo existe
    $stmt = $db->prepare("SELECT * FROM devices WHERE id = ?");
    $stmt->execute([$device_id]);
    $device = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$device) {
        http_response_code(404);
        echo json_encode(['error' => 'Device not found']);
        exit;
    }
    
    // Construir campos a actualizar
    $updates = [];
    $params = [];
    $log_changes = [];
    
    // Procesar campos opcionales
    $fields = ['name', 'type', 'mac_address', 'ip_address', 'location', 'description', 'status'];
    
    foreach ($fields as $field) {
        if (isset($input[$field])) {
            $value = sanitize_input($input[$field]);
            
            // Validaciones específicas
            if ($field === 'mac_address' && !empty($value)) {
                if (!preg_match('/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/', $value)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'Invalid MAC address format']);
                    exit;
                }
                $value = strtoupper($value);
                
                // Verificar MAC única
                $stmt = $db->prepare("SELECT id FROM devices WHERE mac_address = ? AND id != ?");
                $stmt->execute([$value, $device_id]);
                if ($stmt->fetch()) {
                    http_response_code(409);
                    echo json_encode(['error' => 'MAC address already in use']);
                    exit;
                }
            }
            
            if ($field === 'ip_address' && !empty($value)) {
                if (!filter_var($value, FILTER_VALIDATE_IP)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'Invalid IP address format']);
                    exit;
                }
            }
            
            if ($field === 'status' && !in_array($value, ['active', 'inactive'])) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid status value']);
                exit;
            }
            
            // Si el valor cambió, agregarlo a updates
            if ($device[$field] !== $value) {
                $updates[] = "$field = ?";
                $params[] = $value ?: null;
                $log_changes[$field] = [
                    'old' => $device[$field],
                    'new' => $value
                ];
            }
        }
    }
    
    // Si no hay cambios
    if (empty($updates)) {
        echo json_encode([
            'success' => true,
            'message' => 'No changes to update'
        ]);
        exit;
    }
    
    // Actualizar dispositivo
    $updates[] = "updated_at = NOW()";
    $params[] = $device_id;
    
    $query = "UPDATE devices SET " . implode(", ", $updates) . " WHERE id = ?";
    $stmt = $db->prepare($query);
    $stmt->execute($params);
    
    // Log de actividad
    log_activity('device_updated', $user['id'], [
        'device_id' => $device_id,
        'device_name' => $device['name'],
        'changes' => $log_changes
    ]);
    
    // Respuesta exitosa
    echo json_encode([
        'success' => true,
        'message' => 'Device updated successfully',
        'changes' => count($log_changes)
    ]);
    
} catch (Exception $e) {
    error_log("Update device error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Failed to update device',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
    ]);
}
