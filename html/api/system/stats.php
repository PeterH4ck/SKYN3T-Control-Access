// ===========================
// ARCHIVO: /var/www/html/api/system/stats.php
// DESCRIPCIÓN: Estadísticas del sistema
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

// Solo permitir GET
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
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

try {
    $db = Database::getInstance()->getConnection();
    $stats = [];
    
    // Total usuarios
    $stmt = $db->query("SELECT COUNT(*) as total FROM users");
    $stats['total_users'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['total'];
    
    // Usuarios por rol
    $stmt = $db->query("
        SELECT role, COUNT(*) as count 
        FROM users 
        GROUP BY role
    ");
    $stats['users_by_role'] = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $stats['users_by_role'][$row['role']] = (int)$row['count'];
    }
    
    // Sesiones activas
    $stmt = $db->query("SELECT COUNT(*) as active FROM sessions WHERE is_active = 1");
    $stats['active_sessions'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['active'];
    
    // Total dispositivos
    $stmt = $db->query("SELECT COUNT(*) as total FROM devices");
    $stats['total_devices'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['total'];
    
    // Dispositivos por tipo
    $stmt = $db->query("
        SELECT type, COUNT(*) as count 
        FROM devices 
        GROUP BY type
    ");
    $stats['devices_by_type'] = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $stats['devices_by_type'][$row['type']] = (int)$row['count'];
    }
    
    // Cambios de relé hoy
    $stmt = $db->query("
        SELECT COUNT(*) as changes 
        FROM relay_status 
        WHERE DATE(changed_at) = CURDATE()
    ");
    $stats['relay_changes_today'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['changes'];
    
    // Actividad de las últimas 24 horas
    $stmt = $db->query("
        SELECT COUNT(*) as actions 
        FROM access_log 
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ");
    $stats['actions_24h'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['actions'];
    
    // Logins de las últimas 24 horas
    $stmt = $db->query("
        SELECT COUNT(*) as logins 
        FROM access_log 
        WHERE action = 'login' 
        AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ");
    $stats['logins_24h'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['logins'];
    
    // Sistema uptime (simulado basado en logs más antiguos)
    $stmt = $db->query("SELECT MIN(created_at) as oldest FROM access_log");
    $oldest = $stmt->fetch(PDO::FETCH_ASSOC)['oldest'];
    if ($oldest) {
        $uptime_seconds = time() - strtotime($oldest);
        $stats['system_uptime'] = format_uptime($uptime_seconds);
    } else {
        $stats['system_uptime'] = 'Just started';
    }
    
    // Tamaño de base de datos
    $stmt = $db->query("
        SELECT 
            SUM(data_length + index_length) / 1024 / 1024 as size_mb
        FROM information_schema.TABLES 
        WHERE table_schema = DATABASE()
    ");
    $size = $stmt->fetch(PDO::FETCH_ASSOC)['size_mb'];
    $stats['database_size'] = number_format($size, 2) . ' MB';
    
    // Estadísticas adicionales para SuperUser
    if ($user['role'] === 'SuperUser') {
        // Intentos de login fallidos (últimas 24h)
        $stmt = $db->query("
            SELECT COUNT(*) as failed 
            FROM access_log 
            WHERE action = 'login_failed' 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        $stats['failed_logins_24h'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['failed'];
        
        // Usuarios bloqueados actualmente
        $stmt = $db->query("
            SELECT COUNT(*) as locked 
            FROM users 
            WHERE locked_until IS NOT NULL 
            AND locked_until > NOW()
        ");
        $stats['locked_users'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['locked'];
        
        // Eventos de seguridad recientes
        try {
            $stmt = $db->query("
                SELECT COUNT(*) as security_events 
                FROM access_log 
                WHERE action IN ('unauthorized_access', 'permission_denied', 'security_alert')
                AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            ");
            $stats['security_events_24h'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['security_events'];
        } catch (Exception $e) {
            $stats['security_events_24h'] = 0;
        }
    }
    
    // Información del servidor
    $stats['server_info'] = [
        'php_version' => PHP_VERSION,
        'server_time' => date('Y-m-d H:i:s'),
        'timezone' => date_default_timezone_get()
    ];
    
    echo json_encode([
        'success' => true,
        'stats' => $stats,
        'generated_at' => date('Y-m-d H:i:s')
    ]);
    
} catch (Exception $e) {
    error_log("System stats error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Failed to retrieve system statistics',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
    ]);
}

// Función para formatear uptime
function format_uptime($seconds) {
    $days = floor($seconds / 86400);
    $hours = floor(($seconds % 86400) / 3600);
    $minutes = floor(($seconds % 3600) / 60);
    
    $parts = [];
    if ($days > 0) $parts[] = $days . ' day' . ($days > 1 ? 's' : '');
    if ($hours > 0) $parts[] = $hours . ' hour' . ($hours > 1 ? 's' : '');
    if ($minutes > 0) $parts[] = $minutes . ' minute' . ($minutes > 1 ? 's' : '');
    
    return implode(', ', $parts) ?: 'Just started';
}
