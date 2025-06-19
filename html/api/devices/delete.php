// ===========================
// ARCHIVO: /var/www/html/api/devices/delete.php (MEJORADO)
// DESCRIPCIÓN: Eliminar dispositivo
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

// Solo permitir DELETE o POST
if (!in_array($_SERVER['REQUEST_METHOD'], ['DELETE', 'POST'])) {
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

// Solo SuperUser puede eliminar dispositivos
if ($user['role'] !== 'SuperUser') {
    http_response_code(403);
    echo json_encode(['error' => 'Only SuperUser can delete devices']);
    security_log('device_delete_denied', $user['id'], ['role' => $user['role']]);
    exit;
}

// Obtener device_id
$input = get_json_input();
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
    
    // Iniciar transacción
    $db->beginTransaction();
    
    try {
        // Guardar información del dispositivo antes de eliminar
        $device_info = json_encode($device);
        
        // Eliminar logs relacionados si existen
        $stmt = $db->prepare("DELETE FROM device_logs WHERE device_id = ?");
        $stmt->execute([$device_id]);
        $logs_deleted = $stmt->rowCount();
        
        // Eliminar el dispositivo
        $stmt = $db->prepare("DELETE FROM devices WHERE id = ?");
        $stmt->execute([$device_id]);
        
        // Confirmar transacción
        $db->commit();
        
        // Log de actividad
        log_activity('device_deleted', $user['id'], [
            'device_id' => $device_id,
            'device_name' => $device['name'],
            'device_type' => $device['type'],
            'device_info' => $device_info,
            'logs_deleted' => $logs_deleted
        ]);
        
        // Log de seguridad
        security_log('device_deleted', $user['id'], [
            'device_id' => $device_id,
            'device_name' => $device['name']
        ]);
        
        echo json_encode([
            'success' => true,
            'message' => 'Device deleted successfully',
            'deleted' => [
                'device_id' => $device_id,
                'device_name' => $device['name'],
                'logs_deleted' => $logs_deleted
            ]
        ]);
        
    } catch (Exception $e) {
        $db->rollBack();
        throw $e;
    }
    
} catch (Exception $e) {
    error_log("Delete device error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Failed to delete device',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
    ]);
}
