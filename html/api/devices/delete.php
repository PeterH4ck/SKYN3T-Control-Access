<?php
/**
 * Archivo: /var/www/html/api/devices/delete.php
 * API endpoint para eliminar dispositivos
 */

// Definir constante del sistema
define('SKYN3T_SYSTEM', true);

// Headers de seguridad y CORS
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: DELETE, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Manejo de solicitudes OPTIONS (CORS preflight)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Permitir DELETE y POST
if (!in_array($_SERVER['REQUEST_METHOD'], ['DELETE', 'POST'])) {
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
            'message' => 'Sin permisos para eliminar dispositivos',
            'error_code' => 'INSUFFICIENT_PERMISSIONS'
        ]);
        exit;
    }
    
    // Obtener ID del dispositivo
    $deviceId = null;
    
    if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
        // Para DELETE, obtener ID de la URL o del body
        $input = json_decode(file_get_contents('php://input'), true);
        $deviceId = $input['id'] ?? $_GET['id'] ?? null;
    } else {
        // Para POST, obtener del body JSON
        $input = json_decode(file_get_contents('php://input'), true);
        $deviceId = $input['id'] ?? null;
    }
    
    if (!$deviceId) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'message' => 'ID del dispositivo requerido',
            'error_code' => 'DEVICE_ID_REQUIRED'
        ]);
        exit;
    }
    
    $deviceId = (int)$deviceId;
    
    $db = Database::getInstance();
    
    // Verificar que el dispositivo existe y obtener información
    $device = $db->fetch("
        SELECT d.*, u.username as created_by_username
        FROM devices d
        LEFT JOIN users u ON d.created_by = u.id
        WHERE d.id = ?
    ", [$deviceId]);
    
    if (!$device) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'message' => 'Dispositivo no encontrado',
            'error_code' => 'DEVICE_NOT_FOUND'
        ]);
        exit;
    }
    
    // Verificar si es un dispositivo crítico del sistema
    $criticalDevices = ['Relé Principal', 'Sistema Principal', 'Control Principal'];
    if (in_array($device['device_name'], $criticalDevices)) {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'message' => 'No se puede eliminar un dispositivo crítico del sistema',
            'error_code' => 'CRITICAL_DEVICE_PROTECTION'
        ]);
        exit;
    }
    
    // Obtener parámetro de confirmación (opcional)
    $force = false;
    if (isset($input['force']) && $input['force'] === true) {
        $force = true;
    }
    
    // Si no es forzado, verificar dependencias
    if (!$force) {
        // Verificar si hay registros relacionados (logs, eventos, etc.)
        $relatedRecords = $db->fetch("
            SELECT COUNT(*) as count 
            FROM relay_status 
            WHERE changed_by = (
                SELECT created_by FROM devices WHERE id = ?
            )
        ", [$deviceId]);
        
        if ($relatedRecords['count'] > 0) {
            echo json_encode([
                'success' => false,
                'message' => 'El dispositivo tiene registros relacionados. Use force=true para eliminar',
                'error_code' => 'DEVICE_HAS_DEPENDENCIES',
                'related_records' => (int)$relatedRecords['count'],
                'force_required' => true
            ]);
            exit;
        }
    }
    
    // Realizar backup de la información antes de eliminar
    $deviceBackup = [
        'id' => $device['id'],
        'device_name' => $device['device_name'],
        'device_type' => $device['device_type'],
        'mac_address' => $device['mac_address'],
        'ip_address' => $device['ip_address'],
        'status' => $device['status'],
        'location' => $device['location'],
        'description' => $device['description'],
        'created_at' => $device['created_at'],
        'updated_at' => $device['updated_at'],
        'created_by' => $device['created_by'],
        'created_by_username' => $device['created_by_username'],
        'deleted_at' => date('Y-m-d H:i:s'),
        'deleted_by' => $user['id']
    ];
    
    // Iniciar transacción
    $db->beginTransaction();
    
    try {
        // Opcional: Guardar en tabla de dispositivos eliminados (audit)
        $db->executeQuery("
            INSERT INTO devices_deleted (
                original_id, device_name, device_type, mac_address, ip_address,
                status, location, description, created_at, updated_at,
                created_by, deleted_at, deleted_by, backup_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ", [
            $device['id'], $device['device_name'], $device['device_type'],
            $device['mac_address'], $device['ip_address'], $device['status'],
            $device['location'], $device['description'], $device['created_at'],
            $device['updated_at'], $device['created_by'], date('Y-m-d H:i:s'),
            $user['id'], json_encode($deviceBackup)
        ]);
        
        // Eliminar el dispositivo
        $rowsAffected = $db->update("DELETE FROM devices WHERE id = ?", [$deviceId]);
        
        if ($rowsAffected === 0) {
            throw new Exception('No se pudo eliminar el dispositivo');
        }
        
        // Confirmar transacción
        $db->commit();
        
        // Log de eliminación
        Security::logSecurityEvent('device_deleted', [
            'user_id' => $user['id'],
            'username' => $user['username'],
            'device_id' => $deviceId,
            'device_name' => $device['device_name'],
            'device_type' => $device['device_type'],
            'forced' => $force,
            'backup_created' => true
        ], 'WARNING');
        
        // Respuesta exitosa
        echo json_encode([
            'success' => true,
            'message' => 'Dispositivo eliminado exitosamente',
            'deleted_device' => [
                'id' => (int)$device['id'],
                'device_name' => $device['device_name'],
                'device_type' => $device['device_type']
            ],
            'backup_created' => true,
            'deleted_by' => [
                'id' => $user['id'],
                'username' => $user['username']
            ],
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        
    } catch (Exception $e) {
        // Revertir transacción
        $db->rollback();
        throw $e;
    }
    
} catch (Exception $e) {
    error_log("Error eliminando dispositivo: " . $e->getMessage());
    
    // Log del error
    Security::logSecurityEvent('device_delete_error', [
        'error' => $e->getMessage(),
        'user_id' => $user['id'] ?? null,
        'device_id' => $deviceId ?? null
    ], 'ERROR');
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Error interno del servidor',
        'error_code' => 'INTERNAL_ERROR'
    ]);
}

// Crear tabla de audit para dispositivos eliminados si no existe
try {
    $db = Database::getInstance();
    $db->executeQuery("
        CREATE TABLE IF NOT EXISTS devices_deleted (
            id INT AUTO_INCREMENT PRIMARY KEY,
            original_id INT NOT NULL,
            device_name VARCHAR(100) NOT NULL,
            device_type VARCHAR(50) NOT NULL,
            mac_address VARCHAR(17),
            ip_address VARCHAR(15),
            status ENUM('active','inactive','maintenance'),
            location VARCHAR(100),
            description TEXT,
            created_at TIMESTAMP,
            updated_at TIMESTAMP,
            created_by INT,
            deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            deleted_by INT,
            backup_data LONGTEXT,
            INDEX idx_original_id (original_id),
            INDEX idx_deleted_at (deleted_at),
            INDEX idx_deleted_by (deleted_by)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");
} catch (Exception $e) {
    error_log("Error creando tabla devices_deleted: " . $e->getMessage());
}
?>
