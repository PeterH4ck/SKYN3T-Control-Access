// ===========================
// ARCHIVO: /var/www/html/api/devices/add.php (MEJORADO)
// DESCRIPCIÓN: Agregar nuevo dispositivo
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

// Solo permitir POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
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

// Obtener datos
$input = get_json_input();

// Validaciones
$errors = [];

$name = sanitize_input($input['name'] ?? '');
$type = sanitize_input($input['type'] ?? '');
$mac_address = sanitize_input($input['mac_address'] ?? '');
$ip_address = sanitize_input($input['ip_address'] ?? '');
$location = sanitize_input($input['location'] ?? '');
$description = sanitize_input($input['description'] ?? '');

// Validar campos requeridos
if (empty($name)) {
    $errors[] = 'Device name is required';
}

if (empty($type)) {
    $errors[] = 'Device type is required';
}

if (empty($mac_address)) {
    $errors[] = 'MAC address is required';
} elseif (!preg_match('/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/', $mac_address)) {
    $errors[] = 'Invalid MAC address format';
}

// Validar IP si se proporciona
if (!empty($ip_address) && !filter_var($ip_address, FILTER_VALIDATE_IP)) {
    $errors[] = 'Invalid IP address format';
}

if (!empty($errors)) {
    http_response_code(400);
    echo json_encode(['error' => 'Validation failed', 'errors' => $errors]);
    exit;
}

try {
    $db = Database::getInstance()->getConnection();
    
    // Verificar si ya existe un dispositivo con esa MAC
    $stmt = $db->prepare("SELECT id FROM devices WHERE mac_address = ?");
    $stmt->execute([$mac_address]);
    
    if ($stmt->fetch()) {
        http_response_code(409);
        echo json_encode(['error' => 'Device with this MAC address already exists']);
        exit;
    }
    
    // Insertar dispositivo
    $stmt = $db->prepare("
        INSERT INTO devices (name, type, mac_address, ip_address, location, description, status, added_by, created_at, updated_at) 
        VALUES (?, ?, ?, ?, ?, ?, 'active', ?, NOW(), NOW())
    ");
    
    $stmt->execute([
        $name,
        $type,
        strtoupper($mac_address), // Normalizar MAC a mayúsculas
        $ip_address ?: null,
        $location ?: null,
        $description ?: null,
        $user['id']
    ]);
    
    $device_id = $db->lastInsertId();
    
    // Log de actividad
    log_activity('device_added', $user['id'], [
        'device_id' => $device_id,
        'device_name' => $name,
        'device_type' => $type
    ]);
    
    // Respuesta exitosa
    echo json_encode([
        'success' => true,
        'device_id' => (int)$device_id,
        'message' => 'Device added successfully'
    ]);
    
} catch (Exception $e) {
    error_log("Add device error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Failed to add device',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
    ]);
}
