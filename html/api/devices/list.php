<?php
/**
 * Archivo: /var/www/html/api/devices/list.php
 * API endpoint para listar dispositivos
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
    
    // Verificar permisos para ver dispositivos
    if (!$auth->hasPermission($user, 'view_devices') && 
        !$auth->hasPermission($user, 'manage_devices') && 
        !$auth->hasPermission($user, 'all')) {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'message' => 'Sin permisos para ver dispositivos',
            'error_code' => 'INSUFFICIENT_PERMISSIONS'
        ]);
        exit;
    }
    
    $db = Database::getInstance();
    
    // Parámetros de filtrado y paginación
    $page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
    $limit = isset($_GET['limit']) ? max(1, min(100, (int)$_GET['limit'])) : 20;
    $offset = ($page - 1) * $limit;
    
    $status = isset($_GET['status']) ? sanitize($_GET['status']) : null;
    $type = isset($_GET['type']) ? sanitize($_GET['type']) : null;
    $search = isset($_GET['search']) ? sanitize($_GET['search']) : null;
    $sortBy = isset($_GET['sort']) ? sanitize($_GET['sort']) : 'created_at';
    $sortOrder = isset($_GET['order']) && strtolower($_GET['order']) === 'asc' ? 'ASC' : 'DESC';
    
    // Validar campo de ordenamiento
    $allowedSortFields = ['id', 'device_name', 'device_type', 'status', 'created_at', 'updated_at'];
    if (!in_array($sortBy, $allowedSortFields)) {
        $sortBy = 'created_at';
    }
    
    // Construir consulta WHERE
    $whereConditions = [];
    $params = [];
    
    if ($status && in_array($status, ['active', 'inactive', 'maintenance'])) {
        $whereConditions[] = "status = ?";
        $params[] = $status;
    }
    
    if ($type) {
        $whereConditions[] = "device_type = ?";
        $params[] = $type;
    }
    
    if ($search) {
        $whereConditions[] = "(device_name LIKE ? OR description LIKE ? OR ip_address LIKE ? OR mac_address LIKE ?)";
        $searchTerm = "%$search%";
        $params[] = $searchTerm;
        $params[] = $searchTerm;
        $params[] = $searchTerm;
        $params[] = $searchTerm;
    }
    
    $whereClause = empty($whereConditions) ? '' : 'WHERE ' . implode(' AND ', $whereConditions);
    
    // Consulta principal con información del creador
    $sql = "
        SELECT d.*, u.username as created_by_username, u.name as created_by_name
        FROM devices d
        LEFT JOIN users u ON d.created_by = u.id
        $whereClause
        ORDER BY d.$sortBy $sortOrder
        LIMIT $limit OFFSET $offset
    ";
    
    $devices = $db->fetchAll($sql, $params);
    
    // Contar total de dispositivos
    $countSql = "SELECT COUNT(*) as total FROM devices d $whereClause";
    $totalResult = $db->fetch($countSql, $params);
    $total = $totalResult['total'];
    
    // Obtener estadísticas
    $stats = $db->fetch("
        SELECT 
            COUNT(*) as total_devices,
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_devices,
            SUM(CASE WHEN status = 'inactive' THEN 1 ELSE 0 END) as inactive_devices,
            SUM(CASE WHEN status = 'maintenance' THEN 1 ELSE 0 END) as maintenance_devices,
            COUNT(DISTINCT device_type) as unique_types
        FROM devices
    ");
    
    // Obtener tipos de dispositivos únicos
    $types = $db->fetchAll("
        SELECT device_type, COUNT(*) as count 
        FROM devices 
        GROUP BY device_type 
        ORDER BY count DESC
    ");
    
    // Formatear respuesta de dispositivos
    $formattedDevices = array_map(function($device) {
        return [
            'id' => (int)$device['id'],
            'device_name' => $device['device_name'],
            'device_type' => $device['device_type'],
            'mac_address' => $device['mac_address'],
            'ip_address' => $device['ip_address'],
            'status' => $device['status'],
            'location' => $device['location'],
            'description' => $device['description'],
            'created_at' => $device['created_at'],
            'updated_at' => $device['updated_at'],
            'created_by' => $device['created_by_username'] ? [
                'id' => (int)$device['created_by'],
                'username' => $device['created_by_username'],
                'name' => $device['created_by_name']
            ] : null,
            'is_online' => checkDeviceOnline($device['ip_address']),
            'last_seen' => getLastSeen($device['id'])
        ];
    }, $devices);
    
    // Calcular información de paginación
    $totalPages = ceil($total / $limit);
    $hasNext = $page < $totalPages;
    $hasPrev = $page > 1;
    
    // Log de acceso
    Security::logSecurityEvent('devices_listed', [
        'user_id' => $user['id'],
        'username' => $user['username'],
        'total_returned' => count($formattedDevices),
        'filters' => [
            'status' => $status,
            'type' => $type,
            'search' => $search ? 'yes' : 'no'
        ]
    ], 'INFO');
    
    // Respuesta exitosa
    echo json_encode([
        'success' => true,
        'devices' => $formattedDevices,
        'pagination' => [
            'current_page' => $page,
            'total_pages' => $totalPages,
            'total_items' => (int)$total,
            'items_per_page' => $limit,
            'has_next' => $hasNext,
            'has_previous' => $hasPrev
        ],
        'statistics' => [
            'total_devices' => (int)$stats['total_devices'],
            'active_devices' => (int)$stats['active_devices'],
            'inactive_devices' => (int)$stats['inactive_devices'],
            'maintenance_devices' => (int)$stats['maintenance_devices'],
            'unique_types' => (int)$stats['unique_types']
        ],
        'device_types' => array_map(function($type) {
            return [
                'type' => $type['device_type'],
                'count' => (int)$type['count']
            ];
        }, $types),
        'filters_applied' => [
            'status' => $status,
            'type' => $type,
            'search' => $search,
            'sort_by' => $sortBy,
            'sort_order' => $sortOrder
        ],
        'timestamp' => date('Y-m-d H:i:s')
    ]);
    
} catch (Exception $e) {
    error_log("Error listando dispositivos: " . $e->getMessage());
    
    // Log del error
    Security::logSecurityEvent('devices_list_error', [
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

/**
 * Verificar si un dispositivo está online (ping simple)
 */
function checkDeviceOnline($ipAddress) {
    if (empty($ipAddress) || $ipAddress === '0.0.0.0') {
        return false;
    }
    
    // En modo desarrollo, simular estado online
    if (getConfig('ENVIRONMENT') === 'development') {
        return rand(0, 1) === 1; // 50% probabilidad
    }
    
    // Ping simple con timeout de 1 segundo
    $command = "ping -c 1 -W 1 " . escapeshellarg($ipAddress) . " > /dev/null 2>&1";
    exec($command, $output, $return_code);
    
    return $return_code === 0;
}

/**
 * Obtener última vez que se vio el dispositivo activo
 */
function getLastSeen($deviceId) {
    // Placeholder - en el futuro se puede implementar un sistema de heartbeat
    // Por ahora retornar null
    return null;
}
?>
