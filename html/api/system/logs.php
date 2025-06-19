// ===========================
// ARCHIVO: /var/www/html/api/system/logs.php
// DESCRIPCIÓN: Acceso a logs del sistema
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

// Solo SuperUser puede ver logs
if ($user['role'] !== 'SuperUser') {
    http_response_code(403);
    echo json_encode(['error' => 'Only SuperUser can access system logs']);
    security_log('logs_access_denied', $user['id'], ['role' => $user['role']]);
    exit;
}

// Parámetros
$type = $_GET['type'] ?? 'all';
$date = $_GET['date'] ?? date('Y-m-d');
$user_id = isset($_GET['user_id']) ? (int)$_GET['user_id'] : null;
$action = $_GET['action'] ?? '';
$page = max(1, (int)($_GET['page'] ?? 1));
$limit = min(100, max(1, (int)($_GET['limit'] ?? 50)));
$offset = ($page - 1) * $limit;

// Validar fecha
if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid date format. Use YYYY-MM-DD']);
    exit;
}

try {
    $db = Database::getInstance()->getConnection();
    
    // Construir query
    $where_conditions = [];
    $params = [];
    
    // Filtro por tipo
    if ($type !== 'all') {
        $type_mapping = [
            'access' => ['login', 'logout', 'page_view'],
            'error' => ['error', 'exception', 'warning'],
            'security' => ['unauthorized_access', 'permission_denied', 'security_alert', 'login_failed'],
            'system' => ['device_added', 'device_updated', 'device_deleted', 'user_created', 'user_updated', 'user_deleted', 'relay_control']
        ];
        
        if (isset($type_mapping[$type])) {
            $placeholders = array_fill(0, count($type_mapping[$type]), '?');
            $where_conditions[] = "al.action IN (" . implode(',', $placeholders) . ")";
            $params = array_merge($params, $type_mapping[$type]);
        }
    }
    
    // Filtro por fecha
    $where_conditions[] = "DATE(al.created_at) = ?";
    $params[] = $date;
    
    // Filtro por usuario
    if ($user_id !== null) {
        $where_conditions[] = "al.user_id = ?";
        $params[] = $user_id;
    }
    
    // Filtro por acción específica
    if (!empty($action)) {
        $where_conditions[] = "al.action LIKE ?";
        $params[] = "%$action%";
    }
    
    $where_clause = "WHERE " . implode(" AND ", $where_conditions);
    
    // Contar total
    $count_query = "SELECT COUNT(*) as total FROM access_log al $where_clause";
    $stmt = $db->prepare($count_query);
    $stmt->execute($params);
    $total = $stmt->fetch(PDO::FETCH_ASSOC)['total'];
    
    // Obtener logs
    $query = "
        SELECT 
            al.*,
            u.username,
            u.full_name,
            u.role as user_role
        FROM access_log al
        LEFT JOIN users u ON u.id = al.user_id
        $where_clause
        ORDER BY al.created_at DESC
        LIMIT ? OFFSET ?
    ";
    
    $params[] = $limit;
    $params[] = $offset;
    
    $stmt = $db->prepare($query);
    $stmt->execute($params);
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Formatear logs
    $formatted_logs = array_map(function($log) {
        $formatted = [
            'id' => (int)$log['id'],
            'action' => $log['action'],
            'user' => $log['user_id'] ? [
                'id' => (int)$log['user_id'],
                'username' => $log['username'] ?? 'Unknown',
                'full_name' => $log['full_name'] ?? 'Unknown User',
                'role' => $log['user_role'] ?? 'Unknown'
            ] : null,
            'ip_address' => $log['ip_address'],
            'user_agent' => $log['user_agent'],
            'created_at' => $log['created_at']
        ];
        
        // Parsear detalles JSON si existen
        if (!empty($log['details'])) {
            try {
                $formatted['details'] = json_decode($log['details'], true);
            } catch (Exception $e) {
                $formatted['details'] = $log['details'];
            }
        }
        
        // Categorizar el tipo de log
        $formatted['category'] = categorize_log($log['action']);
        
        return $formatted;
    }, $logs);
    
    // Estadísticas del día
    $stats_query = "
        SELECT 
            COUNT(*) as total_logs,
            COUNT(DISTINCT user_id) as unique_users,
            COUNT(DISTINCT ip_address) as unique_ips,
            SUM(CASE WHEN action = 'login' THEN 1 ELSE 0 END) as logins,
            SUM(CASE WHEN action = 'login_failed' THEN 1 ELSE 0 END) as failed_logins,
            SUM(CASE WHEN action LIKE '%error%' THEN 1 ELSE 0 END) as errors
        FROM access_log
        WHERE DATE(created_at) = ?
    ";
    
    $stmt = $db->prepare($stats_query);
    $stmt->execute([$date]);
    $daily_stats = $stmt->fetch(PDO::FETCH_ASSOC);
    
    echo json_encode([
        'success' => true,
        'logs' => $formatted_logs,
        'pagination' => [
            'total' => (int)$total,
            'page' => $page,
            'limit' => $limit,
            'pages' => ceil($total / $limit)
        ],
        'filters' => [
            'type' => $type,
            'date' => $date,
            'user_id' => $user_id,
            'action' => $action
        ],
        'daily_stats' => [
            'total_logs' => (int)$daily_stats['total_logs'],
            'unique_users' => (int)$daily_stats['unique_users'],
            'unique_ips' => (int)$daily_stats['unique_ips'],
            'logins' => (int)$daily_stats['logins'],
            'failed_logins' => (int)$daily_stats['failed_logins'],
            'errors' => (int)$daily_stats['errors']
        ]
    ]);
    
} catch (Exception $e) {
    error_log("System logs error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Failed to retrieve system logs',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
    ]);
}

// Función para categorizar logs
function categorize_log($action) {
    $categories = [
        'access' => ['login', 'logout', 'page_view', 'api_access'],
        'error' => ['error', 'exception', 'warning', 'critical_error'],
        'security' => ['unauthorized_access', 'permission_denied', 'security_alert', 'login_failed', 'account_locked'],
        'system' => ['device_added', 'device_updated', 'device_deleted', 'user_created', 'user_updated', 'user_deleted'],
        'relay' => ['relay_control', 'relay_status_changed', 'relay_scheduled'],
        'data' => ['data_imported', 'data_exported', 'backup_created', 'backup_restored']
    ];
    
    foreach ($categories as $category => $actions) {
        if (in_array($action, $actions)) {
            return $category;
        }
    }
    
    // Si no coincide con ninguna categoría conocida
    return 'other';
}
?>
