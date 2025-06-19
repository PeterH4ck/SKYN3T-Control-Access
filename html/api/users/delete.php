// ===========================
// ARCHIVO: /var/www/html/api/users/delete.php
// DESCRIPCIÓN: Eliminar usuario
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

// Solo SuperUser puede eliminar usuarios
if ($user['role'] !== 'SuperUser') {
    http_response_code(403);
    echo json_encode(['error' => 'Only SuperUser can delete users']);
    security_log('user_delete_denied', $user['id'], ['role' => $user['role']]);
    exit;
}

// Obtener user_id
$input = get_json_input();
$user_id = (int)($input['user_id'] ?? 0);

if ($user_id <= 0) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid user ID']);
    exit;
}

// No permitir auto-eliminación
if ($user_id === $user['id']) {
    http_response_code(403);
    echo json_encode(['error' => 'Cannot delete your own account']);
    exit;
}

try {
    $db = Database::getInstance()->getConnection();
    
    // Verificar que el usuario existe
    $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $target_user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$target_user) {
        http_response_code(404);
        echo json_encode(['error' => 'User not found']);
        exit;
    }
    
    // No permitir eliminar el último SuperUser
    if ($target_user['role'] === 'SuperUser') {
        $stmt = $db->prepare("SELECT COUNT(*) as count FROM users WHERE role = 'SuperUser' AND status = 'active'");
        $stmt->execute();
        $count = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
        
        if ($count <= 1) {
            http_response_code(403);
            echo json_encode(['error' => 'Cannot delete the last SuperUser account']);
            exit;
        }
    }
    
    // Iniciar transacción
    $db->beginTransaction();
    
    try {
        // Guardar información del usuario
        $user_info = json_encode($target_user);
        
        // Cerrar todas las sesiones del usuario
        $stmt = $db->prepare("DELETE FROM sessions WHERE user_id = ?");
        $stmt->execute([$user_id]);
        $sessions_deleted = $stmt->rowCount();
        
        // Actualizar referencias en logs (no eliminar logs, solo anonimizar)
        $stmt = $db->prepare("UPDATE access_log SET user_id = NULL WHERE user_id = ?");
        $stmt->execute([$user_id]);
        $logs_updated = $stmt->rowCount();
        
        // Actualizar dispositivos agregados por este usuario
        $stmt = $db->prepare("UPDATE devices SET added_by = NULL WHERE added_by = ?");
        $stmt->execute([$user_id]);
        $devices_updated = $stmt->rowCount();
        
        // Eliminar el usuario
        $stmt = $db->prepare("DELETE FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        
        // Confirmar transacción
        $db->commit();
        
        // Log de actividad
        log_activity('user_deleted', $user['id'], [
            'deleted_user_id' => $user_id,
            'deleted_username' => $target_user['username'],
            'deleted_role' => $target_user['role'],
            'user_info' => $user_info,
            'sessions_deleted' => $sessions_deleted,
            'logs_anonymized' => $logs_updated,
            'devices_updated' => $devices_updated
        ]);
        
        // Log de seguridad crítico
        security_log('user_deleted', $user['id'], [
            'deleted_user' => $target_user['username'],
            'deleted_role' => $target_user['role'],
            'deleted_email' => $target_user['email']
        ]);
        
        echo json_encode([
            'success' => true,
            'message' => 'User deleted successfully',
            'deleted' => [
                'user_id' => $user_id,
                'username' => $target_user['username'],
                'sessions_closed' => $sessions_deleted,
                'logs_anonymized' => $logs_updated,
                'devices_updated' => $devices_updated
            ]
        ]);
        
    } catch (Exception $e) {
        $db->rollBack();
        throw $e;
    }
    
} catch (Exception $e) {
    error_log("Delete user error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Failed to delete user',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
    ]);
}
