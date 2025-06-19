// ===========================
// ARCHIVO: /var/www/html/api/notifications/list.php (MEJORADO)
// DESCRIPCIÓN: Lista de notificaciones del usuario
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

// Parámetros
$status = $_GET['status'] ?? 'all';
$type = $_GET['type'] ?? '';
$page = max(1, (int)($_GET['page'] ?? 1));
$limit = min(50, max(1, (int)($_GET['limit'] ?? 20)));
$offset = ($page - 1) * $limit;

try {
    $db = Database::getInstance()->getConnection();
    
    // Verificar si la tabla notifications existe
    $table_exists = false;
    try {
        $stmt = $db->query("SELECT 1 FROM notifications LIMIT 1");
        $table_exists = true;
    } catch (Exception $e) {
        // Tabla no existe, crear estructura temporal
    }
    
    if (!$table_exists) {
        // Si no existe la tabla, devolver notificaciones simuladas
        $notifications = generate_sample_notifications($user, $page, $limit);
        echo json_encode($notifications);
        exit;
    }
    
    // Construir query
    $where_conditions = ["(target = 'all' OR target = ? OR target LIKE ?)"];
    $params = [$user['username'], '%' . $user['role'] . '%'];
    
    if ($status === 'read' || $status === 'unread') {
        $where_conditions[] = "status = ?";
        $params[] = $status;
    }
    
    if (!empty($type)) {
        $where_conditions[] = "type = ?";
        $params[] = $type;
    }
    
    $where_clause = "WHERE " . implode(" AND ", $where_conditions);
    
    // Contar total
    $count_query = "SELECT COUNT(*) as total FROM notifications $where_clause";
    $stmt = $db->prepare($count_query);
    $stmt->execute($params);
    $total = $stmt->fetch(PDO::FETCH_ASSOC)['total'];
    
    // Obtener notificaciones
    $query = "
        SELECT * FROM notifications 
        $where_clause
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    ";
    
    $params[] = $limit;
    $params[] = $offset;
    
    $stmt = $db->prepare($query);
    $stmt->execute($params);
    $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Contar no leídas
    $stmt = $db->prepare("
        SELECT COUNT(*) as unread 
        FROM notifications 
        WHERE (target = 'all' OR target = ? OR target LIKE ?) 
        AND status = 'unread'
    ");
    $stmt->execute([$user['username'], '%' . $user['role'] . '%']);
    $unread_count = $stmt->fetch(PDO::FETCH_ASSOC)['unread'];
    
    // Formatear notificaciones
    $formatted = array_map(function($notif) {
        return [
            'id' => (int)$notif['id'],
            'type' => $notif['type'],
            'message' => $notif['message'],
            'data' => json_decode($notif['data'], true),
            'status' => $notif['status'],
            'created_at' => $notif['created_at'],
            'read_at' => $notif['read_at']
        ];
    }, $notifications);
    
    echo json_encode([
        'success' => true,
        'notifications' => $formatted,
        'unread_count' => (int)$unread_count,
        'pagination' => [
            'total' => (int)$total,
            'page' => $page,
            'limit' => $limit,
            'pages' => ceil($total / $limit)
        ]
    ]);
    
} catch (Exception $e) {
    error_log("Notifications error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Failed to retrieve notifications',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
    ]);
}

// Función para generar notificaciones de muestra
function generate_sample_notifications($user, $page, $limit) {
    $sample_notifications = [
        [
            'id' => 1,
            'type' => 'system',
            'message' => 'Welcome to SKYN3T System v2.0.0',
            'data' => ['version' => '2.0.0'],
            'status' => 'unread',
            'created_at' => date('Y-m-d H:i:s', strtotime('-1 hour')),
            'read_at' => null
        ],
        [
            'id' => 2,
            'type' => 'relay_change',
            'message' => 'Relay turned on by admin',
            'data' => ['user' => 'admin', 'action' => 'on'],
            'status' => 'read',
            'created_at' => date('Y-m-d H:i:s', strtotime('-2 hours')),
            'read_at' => date('Y-m-d H:i:s', strtotime('-1 hour'))
        ],
        [
            'id' => 3,
            'type' => 'device_added',
            'message' => 'New device added: Security Camera #1',
            'data' => ['device_name' => 'Security Camera #1', 'device_type' => 'camera'],
            'status' => 'unread',
            'created_at' => date('Y-m-d H:i:s', strtotime('-3 hours')),
            'read_at' => null
        ]
    ];
    
    // Paginar manualmente
    $start = ($page - 1) * $limit;
    $paginated = array_slice($sample_notifications, $start, $limit);
    
    return [
        'success' => true,
        'notifications' => $paginated,
        'unread_count' => 2,
        'pagination' => [
            'total' => count($sample_notifications),
            'page' => $page,
            'limit' => $limit,
            'pages' => ceil(count($sample_notifications) / $limit)
        ],
        'note' => 'Using sample notifications - notifications table not found'
    ];
}
