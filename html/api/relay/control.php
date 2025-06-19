// ===========================
// ARCHIVO: /var/www/html/api/relay/control.php
// DESCRIPCIÓN: Control del relé (ON/OFF)
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

// Verificar permisos (Admin o SuperUser)
if (!in_array($user['role'], ['Admin', 'SuperUser'])) {
    http_response_code(403);
    echo json_encode(['error' => 'Insufficient permissions']);
    security_log('relay_control_denied', $user['id'], ['role' => $user['role']]);
    exit;
}

// Obtener datos de la petición
$input = get_json_input();

// Validar acción
$action = $input['action'] ?? '';
if (!in_array($action, ['on', 'off', 'toggle'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid action. Must be: on, off, or toggle']);
    exit;
}

$reason = sanitize_input($input['reason'] ?? 'Manual control');

try {
    $db = Database::getInstance()->getConnection();
    
    // Obtener estado actual del relé
    $stmt = $db->prepare("
        SELECT status 
        FROM relay_status 
        ORDER BY changed_at DESC 
        LIMIT 1
    ");
    $stmt->execute();
    $current = $stmt->fetch(PDO::FETCH_ASSOC);
    $current_status = $current ? $current['status'] : 'off';
    
    // Determinar nuevo estado
    if ($action === 'toggle') {
        $new_status = ($current_status === 'on') ? 'off' : 'on';
    } else {
        $new_status = $action;
    }
    
    // Si el estado no cambia, retornar éxito sin hacer nada
    if ($new_status === $current_status) {
        echo json_encode([
            'success' => true,
            'new_status' => $new_status,
            'message' => 'Relay already in ' . $new_status . ' state',
            'changed' => false
        ]);
        exit;
    }
    
    // Insertar nuevo estado en la base de datos
    $stmt = $db->prepare("
        INSERT INTO relay_status (status, changed_by, reason, changed_at) 
        VALUES (?, ?, ?, NOW())
    ");
    $stmt->execute([$new_status, $user['username'], $reason]);
    
    // Aquí se integraría con el control físico del relé
    // Por ahora, simulamos el control
    $gpio_result = control_relay_gpio($new_status);
    
    // Log de la acción
    log_activity('relay_control', $user['id'], [
        'action' => $action,
        'new_status' => $new_status,
        'reason' => $reason,
        'gpio_result' => $gpio_result
    ]);
    
    // Crear notificación para administradores
    create_notification(
        'relay_change',
        "Relay turned $new_status by {$user['username']}",
        ['reason' => $reason],
        'all_admins'
    );
    
    echo json_encode([
        'success' => true,
        'new_status' => $new_status,
        'message' => 'Relay successfully turned ' . $new_status,
        'changed' => true,
        'gpio_control' => $gpio_result
    ]);
    
} catch (Exception $e) {
    error_log("Relay control error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Failed to control relay',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
    ]);
}

// Función para controlar el GPIO del relé
function control_relay_gpio($status) {
    // Esta función se integraría con el control real del GPIO
    // Por ahora retornamos simulación
    $gpio_pin = 23; // GPIO23 según la documentación
    
    // En producción, aquí se ejecutaría el comando para controlar el GPIO
    // exec("gpio -g write $gpio_pin " . ($status === 'on' ? '1' : '0'), $output, $return_var);
    
    return [
        'simulated' => true,
        'gpio_pin' => $gpio_pin,
        'status' => $status,
        'timestamp' => date('Y-m-d H:i:s')
    ];
}

// Función para crear notificaciones
function create_notification($type, $message, $data, $target = 'all_admins') {
    global $db;
    
    try {
        // Si existe tabla notifications, insertar
        $stmt = $db->prepare("
            INSERT INTO notifications (type, message, data, target, created_at) 
            VALUES (?, ?, ?, ?, NOW())
        ");
        $stmt->execute([$type, $message, json_encode($data), $target]);
        return true;
    } catch (Exception $e) {
        // Si la tabla no existe, solo log
        error_log("Notification not created: " . $e->getMessage());
        return false;
    }
}
