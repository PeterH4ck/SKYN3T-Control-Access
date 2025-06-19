<?php
/**
 * Archivo: /var/www/html/api/users/list.php
 * API endpoint para listar usuarios
 */

// Definir constante del sistema
define('SKYN3T_SYSTEM', true);

// Headers de seguridad y CORS
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Manejo de solicitudes OPTIONS (CORS preflight)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Solo permitir GET
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
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
    
    // Verificar permisos para gestionar usuarios
    if (!$auth->hasPermission($user, 'manage_users') && !$auth->hasPermission($user, 'all')) {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'message' => 'Sin permisos para ver la lista de usuarios',
            'error_code' => 'INSUFFICIENT_PERMISSIONS'
        ]);
        exit;
    }
    
    $db = Database::getInstance();
    
    // Parámetros de filtrado y paginación
    $page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
    $limit = isset($_GET['limit']) ? max(1, min(50, (int)$_GET['limit'])) : 20;
    $offset = ($page - 1) * $limit;
    
    $role = isset($_GET['role']) ? sanitize($_GET['role']) : null;
    $active = isset($_GET['active']) ? (bool)$_GET['active'] : null;
    $search = isset($_GET['search']) ? sanitize($_GET['search']) : null;
    $sortBy = isset($_GET['sort']) ? sanitize($_GET['sort']) : 'created_at';
    $sortOrder = isset($_GET['order']) && strtolower($_GET['order']) === 'asc' ? 'ASC' : 'DESC';
    
    // Validar campo de ordenamiento
    $allowedSortFields = ['id', 'username', 'name', 'email', 'role', 'created_at', 'last_login'];
    if (!in_array($sortBy, $allowedSortFields)) {
        $sortBy = 'created_at';
    }
    
    // Construir consulta WHERE
    $whereConditions = [];
    $params = [];
    
    if ($role && in_array($role, ['SuperUser', 'Admin', 'SupportAdmin', 'User'])) {
        $whereConditions[] = "role = ?";
        $params[] = $role;
    }
    
    if ($active !== null) {
        $whereConditions[] = "active = ?";
        $params[] = $active ? 1 : 0;
    }
    
    if ($search) {
        $whereConditions[] = "(username LIKE ? OR name LIKE ? OR email LIKE ?)";
        $searchTerm = "%$search%";
        $params[] = $searchTerm;
        $params[] = $searchTerm;
        $params[] = $searchTerm;
    }
    
    $whereClause = empty($whereConditions) ? '' : 'WHERE ' . implode(' AND ', $whereConditions);
    
    // Consulta principal (excluir datos sensibles)
    $sql = "
        SELECT 
            id, username, name, email, role, active, is_active,
            last_login, created_at, updated_at, failed_attempts,
            CASE 
                WHEN locked_until > NOW() THEN 1 
                ELSE 0 
            END as is_locked
        FROM users 
        $whereClause
        ORDER BY $sortBy $sortOrder
        LIMIT $limit OFFSET $offset
    ";
    
    $users = $db->fetchAll($sql, $params);
    
    // Contar total de usuarios
    $countSql = "SELECT COUNT(*) as total FROM users $whereClause";
    $totalResult = $db->fetch($countSql, $params);
    $total = $totalResult['total'];
    
    // Obtener estadísticas
    $stats = $db->fetch("
        SELECT 
            COUNT(*) as total_users,
            SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) as active_users,
            SUM(CASE WHEN active = 0 THEN 1 ELSE 0 END) as inactive_users,
            SUM(CASE WHEN locked_until > NOW() THEN 1 ELSE 0 END) as locked_users,
            COUNT(DISTINCT role) as unique_roles
        FROM users
    ");
    
    // Obtener estadísticas por rol
    $roleStats = $db->fetchAll("
        SELECT role, COUNT(*) as count 
        FROM users 
        GROUP BY role 
        ORDER BY count DESC
    ");
    
    // Obtener sesiones activas por usuario
    $sessionStats = $db->fetchAll("
        SELECT s.user_id, COUNT(*) as active_sessions
        FROM sessions s
        WHERE s.expires_at > NOW()
        GROUP BY s.user_id
    ");
    
    // Crear mapa de sesiones activas
    $sessionsMap = [];
    foreach ($sessionStats as $stat) {
        $sessionsMap[$stat['user_id']] = (int)$stat['active_sessions'];
    }
    
    // Formatear respuesta de usuarios
    $formattedUsers = array_map(function($userData) use ($sessionsMap) {
        // Decodificar privilegios si existen
        $privileges = [];
        if (!empty($userData['privileges'])) {
            $privileges = json_decode($userData['privileges'], true) ?: [];
        }
        
        return [
            'id' => (int)$userData['id'],
            'username' => $userData['username'],
            'name' => $userData['name'],
            'email' => $userData['email'],
            'role' => $userData['role'],
            'active' => (bool)$userData['active'],
            'is_active' => (bool)$userData['is_active'],
            'is_locked' => (bool)$userData['is_locked'],
            'failed_attempts' => (int)$userData['failed_attempts'],
            'last_login' => $userData['last_login'],
            'created_at' => $userData['created_at'],
            'updated_at' => $userData['updated_at'],
            'active_sessions' => $sessionsMap[$userData['id']] ?? 0,
            'is_online' => isset($sessionsMap[$userData['id']]) && $sessionsMap[$userData['id']] > 0
        ];
    }, $users);
    
    // Calcular información de paginación
    $totalPages = ceil($total / $limit);
    $hasNext = $page < $totalPages;
    $hasPrev = $page > 1;
    
    // Log de acceso
    Security::logSecurityEvent('users_listed', [
        'user_id' => $user['id'],
        'username' => $user['username'],
        'total_returned' => count($formattedUsers),
        'filters' => [
            'role' => $role,
            'active' => $active,
            'search' => $search ? 'yes' : 'no'
        ]
    ], 'INFO');
    
    // Respuesta exitosa
    echo json_encode([
        'success' => true,
        'users' => $formattedUsers,
        'pagination' => [
            'current_page' => $page,
            'total_pages' => $totalPages,
            'total_items' => (int)$total,
            'items_per_page' => $limit,
            'has_next' => $hasNext,
            'has_previous' => $hasPrev
        ],
        'statistics' => [
            'total_users' => (int)$stats['total_users'],
            'active_users' => (int)$stats['active_users'],
            'inactive_users' => (int)$stats['inactive_users'],
            'locked_users' => (int)$stats['locked_users'],
            'unique_roles' => (int)$stats['unique_roles']
        ],
        'role_distribution' => array_map(function($role) {
            return [
                'role' => $role['role'],
                'count' => (int)$role['count']
            ];
        }, $roleStats),
        'filters_applied' => [
            'role' => $role,
            'active' => $active,
            'search' => $search,
            'sort_by' => $sortBy,
            'sort_order' => $sortOrder
        ],
        'current_user' => [
            'id' => $user['id'],
            'username' => $user['username'],
            'role' => $user['role']
        ],
        'timestamp' => date('Y-m-d H:i:s')
    ]);
    
} catch (Exception $e) {
    error_log("Error listando usuarios: " . $e->getMessage());
    
    // Log del error
    Security::logSecurityEvent('users_list_error', [
        'error' => $e->getMessage(),
        'user_id' => $user['id'] ?? null
    ], 'ERROR');
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Error interno del servidor',
        'error_code' => 'INTERNAL_ERROR'
    ]);
}
?>
