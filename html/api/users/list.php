// ===========================
// ARCHIVO: /var/www/html/api/users/list.php
// DESCRIPCIÓN: Listar usuarios del sistema
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

// Parámetros
$role = $_GET['role'] ?? '';
$status = $_GET['status'] ?? 'all';
$search = $_GET['search'] ?? '';
$page = max(1, (int)($_GET['page'] ?? 1));
$limit = min(100, max(1, (int)($_GET['limit'] ?? 20)));
$offset = ($page - 1) * $limit;

try {
    $db = Database::getInstance()->getConnection();
    
    // Construir query
    $where_conditions = [];
    $params = [];
    
    if ($status !== 'all') {
        $where_conditions[] = "u.status = ?";
        $params[] = $status;
    }
    
    if (!empty($role)) {
        $where_conditions[] = "u.role = ?";
        $params[] = $role;
    }
    
    if (!empty($search)) {
        $where_conditions[] = "(u.username LIKE ? OR u.email LIKE ? OR u.full_name LIKE ?)";
        $search_param = "%$search%";
        $params = array_merge($params, [$search_param, $search_param, $search_param]);
    }
    
    // Admins no pueden ver SuperUsers
    if ($user['role'] === 'Admin') {
        $where_conditions[] = "u.role != 'SuperUser'";
    }
    
    $where_clause = !empty($where_conditions) ? "WHERE " . implode(" AND ", $where_conditions) : "";
    
    // Contar total
    $count_query = "SELECT COUNT(*) as total FROM users u $where_clause";
    $stmt = $db->prepare($count_query);
    $stmt->execute($params);
    $total = $stmt->fetch(PDO::FETCH_ASSOC)['total'];
    
    // Obtener usuarios
    $query = "
        SELECT 
            u.id,
            u.username,
            u.email,
            u.full_name,
            u.role,
            u.status,
            u.phone,
            u.created_at,
            u.last_login,
            u.login_count,
            u.failed_login_count,
            u.locked_until,
            (SELECT COUNT(*) FROM sessions WHERE user_id = u.id AND is_active = 1) as active_sessions,
            (SELECT COUNT(*) FROM access_log WHERE user_id = u.id AND DATE(created_at) = CURDATE()) as actions_today
        FROM users u
        $where_clause
        ORDER BY u.created_at DESC
        LIMIT ? OFFSET ?
    ";
    
    $params[] = $limit;
    $params[] = $offset;
    
    $stmt = $db->prepare($query);
    $stmt->execute($params);
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Formatear usuarios (sin incluir contraseñas)
    $formatted_users = array_map(function($u) use ($user) {
        $formatted = [
            'id' => (int)$u['id'],
            'username' => $u['username'],
            'email' => $u['email'],
            'full_name' => $u['full_name'],
            'role' => $u['role'],
            'status' => $u['status'],
            'phone' => $u['phone'],
            'created_at' => $u['created_at'],
            'last_login' => $u['last_login'],
            'statistics' => [
                'login_count' => (int)$u['login_count'],
                'failed_login_count' => (int)$u['failed_login_count'],
                'active_sessions' => (int)$u['active_sessions'],
                'actions_today' => (int)$u['actions_today']
            ],
            'is_locked' => !empty($u['locked_until']) && strtotime($u['locked_until']) > time()
        ];
        
        // Solo SuperUser puede ver información de bloqueo
        if ($user['role'] === 'SuperUser' && $formatted['is_locked']) {
            $formatted['locked_until'] = $u['locked_until'];
        }
        
        return $formatted;
    }, $users);
    
    echo json_encode([
        'success' => true,
        'users' => $formatted_users,
        'pagination' => [
            'total' => (int)$total,
            'page' => $page,
            'limit' => $limit,
            'pages' => ceil($total / $limit)
        ],
        'filters' => [
            'role' => $role,
            'status' => $status,
            'search' => $search
        ]
    ]);
    
} catch (Exception $e) {
    error_log("User list error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Failed to retrieve users',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
    ]);
}
