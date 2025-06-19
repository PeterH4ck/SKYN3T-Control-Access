// ===========================
// ARCHIVO: /var/www/html/api/devices/list.php (MEJORADO)
// DESCRIPCIÓN: Listar dispositivos con paginación y filtros
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

// Parámetros de filtro y paginación
$status = $_GET['status'] ?? 'all';
$type = $_GET['type'] ?? '';
$search = $_GET['search'] ?? '';
$page = max(1, (int)($_GET['page'] ?? 1));
$limit = min(100, max(1, (int)($_GET['limit'] ?? 10)));
$offset = ($page - 1) * $limit;

try {
    $db = Database::getInstance()->getConnection();
    
    // Construir query base
    $where_conditions = [];
    $params = [];
    
    if ($status !== 'all') {
        $where_conditions[] = "d.status = ?";
        $params[] = $status;
    }
    
    if (!empty($type)) {
        $where_conditions[] = "d.type = ?";
        $params[] = $type;
    }
    
    if (!empty($search)) {
        $where_conditions[] = "(d.name LIKE ? OR d.mac_address LIKE ? OR d.ip_address LIKE ?)";
        $search_param = "%$search%";
        $params = array_merge($params, [$search_param, $search_param, $search_param]);
    }
    
    $where_clause = !empty($where_conditions) ? "WHERE " . implode(" AND ", $where_conditions) : "";
    
    // Contar total de registros
    $count_query = "SELECT COUNT(*) as total FROM devices d $where_clause";
    $stmt = $db->prepare($count_query);
    $stmt->execute($params);
    $total = $stmt->fetch(PDO::FETCH_ASSOC)['total'];
    
    // Obtener dispositivos
    $query = "
        SELECT 
            d.*,
            u.username as added_by_username,
            u.full_name as added_by_name,
            (SELECT COUNT(*) FROM device_logs WHERE device_id = d.id) as log_count,
            (SELECT MAX(created_at) FROM device_logs WHERE device_id = d.id) as last_activity
        FROM devices d
        LEFT JOIN users u ON u.id = d.added_by
        $where_clause
        ORDER BY d.created_at DESC
        LIMIT ? OFFSET ?
    ";
    
    $params[] = $limit;
    $params[] = $offset;
    
    $stmt = $db->prepare($query);
    $stmt->execute($params);
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Formatear dispositivos
    $formatted_devices = array_map(function($device) {
        return [
            'id' => (int)$device['id'],
            'name' => $device['name'],
            'type' => $device['type'],
            'mac_address' => $device['mac_address'],
            'ip_address' => $device['ip_address'],
            'location' => $device['location'],
            'description' => $device['description'],
            'status' => $device['status'],
            'added_by' => [
                'id' => (int)$device['added_by'],
                'username' => $device['added_by_username'],
                'full_name' => $device['added_by_name']
            ],
            'created_at' => $device['created_at'],
            'updated_at' => $device['updated_at'],
            'log_count' => (int)$device['log_count'],
            'last_activity' => $device['last_activity'],
            'online' => check_device_online($device['ip_address'])
        ];
    }, $devices);
    
    // Calcular páginas
    $total_pages = ceil($total / $limit);
    
    // Respuesta
    echo json_encode([
        'success' => true,
        'devices' => $formatted_devices,
        'pagination' => [
            'total' => (int)$total,
            'page' => $page,
            'limit' => $limit,
            'pages' => $total_pages,
            'has_next' => $page < $total_pages,
            'has_prev' => $page > 1
        ],
        'filters' => [
            'status' => $status,
            'type' => $type,
            'search' => $search
        ]
    ]);
    
} catch (Exception $e) {
    error_log("Device list error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Failed to retrieve devices',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
    ]);
}

// Función para verificar si el dispositivo está online
function check_device_online($ip_address) {
    // En producción, esto haría un ping real
    // Por ahora, simulamos con probabilidad aleatoria
    if (empty($ip_address)) {
        return false;
    }
    
    // Simular estado online (70% de probabilidad de estar online)
    return rand(1, 10) <= 7;
}
