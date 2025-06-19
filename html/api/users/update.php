// ===========================
// ARCHIVO: /var/www/html/api/users/update.php
// DESCRIPCIÓN: Actualizar usuario existente
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

// Solo permitir PUT o POST
if (!in_array($_SERVER['REQUEST_METHOD'], ['PUT', 'POST'])) {
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

// Validar user_id
$user_id = (int)($input['user_id'] ?? 0);
if ($user_id <= 0) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid user ID']);
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
    
    // Validar permisos especiales
    if ($target_user['role'] === 'SuperUser' && $user['role'] !== 'SuperUser') {
        http_response_code(403);
        echo json_encode(['error' => 'Only SuperUser can modify SuperUser accounts']);
        exit;
    }
    
    // No permitir que usuarios se modifiquen a sí mismos ciertos campos
    if ($user_id === $user['id'] && isset($input['role'])) {
        http_response_code(403);
        echo json_encode(['error' => 'Cannot change your own role']);
        exit;
    }
    
    // Construir actualizaciones
    $updates = [];
    $params = [];
    $log_changes = [];
    
    // Email
    if (isset($input['email'])) {
        $email = sanitize_input($input['email']);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid email format']);
            exit;
        }
        
        // Verificar email único
        $stmt = $db->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
        $stmt->execute([$email, $user_id]);
        if ($stmt->fetch()) {
            http_response_code(409);
            echo json_encode(['error' => 'Email already in use']);
            exit;
        }
        
        if ($target_user['email'] !== $email) {
            $updates[] = "email = ?";
            $params[] = $email;
            $log_changes['email'] = ['old' => $target_user['email'], 'new' => $email];
        }
    }
    
    // Full name
    if (isset($input['full_name'])) {
        $full_name = sanitize_input($input['full_name']);
        if ($target_user['full_name'] !== $full_name) {
            $updates[] = "full_name = ?";
            $params[] = $full_name;
            $log_changes['full_name'] = ['old' => $target_user['full_name'], 'new' => $full_name];
        }
    }
    
    // Phone
    if (isset($input['phone'])) {
        $phone = sanitize_input($input['phone']);
        if ($target_user['phone'] !== $phone) {
            $updates[] = "phone = ?";
            $params[] = $phone ?: null;
            $log_changes['phone'] = ['old' => $target_user['phone'], 'new' => $phone];
        }
    }
    
    // Role
    if (isset($input['role'])) {
        $role = sanitize_input($input['role']);
        $valid_roles = ['User', 'SupportAdmin', 'Admin', 'SuperUser'];
        
        if (!in_array($role, $valid_roles)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid role']);
            exit;
        }
        
        // Admins no pueden asignar SuperUser
        if ($user['role'] === 'Admin' && $role === 'SuperUser') {
            http_response_code(403);
            echo json_encode(['error' => 'Admins cannot assign SuperUser role']);
            exit;
        }
        
        if ($target_user['role'] !== $role) {
            $updates[] = "role = ?";
            $params[] = $role;
            $log_changes['role'] = ['old' => $target_user['role'], 'new' => $role];
        }
    }
    
    // Status
    if (isset($input['status'])) {
        $status = sanitize_input($input['status']);
        if (!in_array($status, ['active', 'inactive'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid status']);
            exit;
        }
        
        if ($user_id === $user['id'] && $status === 'inactive') {
            http_response_code(403);
            echo json_encode(['error' => 'Cannot deactivate your own account']);
            exit;
        }
        
        if ($target_user['status'] !== $status) {
            $updates[] = "status = ?";
            $params[] = $status;
            $log_changes['status'] = ['old' => $target_user['status'], 'new' => $status];
        }
    }
    
    // Password
    if (isset($input['password']) && !empty($input['password'])) {
        $password = $input['password'];
        $password_strength = validate_password_strength($password);
        
        if (!$password_strength['valid']) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid password', 'errors' => $password_strength['errors']]);
            exit;
        }
        
        $password_hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        $updates[] = "password = ?";
        $params[] = $password_hash;
        $log_changes['password'] = 'changed';
    }
    
    // Si no hay cambios
    if (empty($updates)) {
        echo json_encode([
            'success' => true,
            'message' => 'No changes to update'
        ]);
        exit;
    }
    
    // Actualizar usuario
    $updates[] = "updated_at = NOW()";
    $params[] = $user_id;
    
    $query = "UPDATE users SET " . implode(", ", $updates) . " WHERE id = ?";
    $stmt = $db->prepare($query);
    $stmt->execute($params);
    
    // Si se cambió el status a inactivo, cerrar sesiones
    if (isset($log_changes['status']) && $log_changes['status']['new'] === 'inactive') {
        $stmt = $db->prepare("UPDATE sessions SET is_active = 0 WHERE user_id = ?");
        $stmt->execute([$user_id]);
    }
    
    // Log de actividad
    log_activity('user_updated', $user['id'], [
        'target_user_id' => $user_id,
        'target_username' => $target_user['username'],
        'changes' => $log_changes
    ]);
    
    // Log de seguridad para cambios críticos
    if (isset($log_changes['role']) || isset($log_changes['status'])) {
        security_log('user_modified', $user['id'], [
            'target_user' => $target_user['username'],
            'critical_changes' => array_intersect_key($log_changes, ['role' => 1, 'status' => 1])
        ]);
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'User updated successfully',
        'changes' => count($log_changes)
    ]);
    
} catch (Exception $e) {
    error_log("Update user error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Failed to update user',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
    ]);
}
