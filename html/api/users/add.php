// ===========================
// ARCHIVO: /var/www/html/api/users/add.php
// DESCRIPCIÓN: Agregar nuevo usuario
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

$username = sanitize_input($input['username'] ?? '');
$password = $input['password'] ?? ''; // No sanitizar passwords
$email = sanitize_input($input['email'] ?? '');
$full_name = sanitize_input($input['full_name'] ?? '');
$role = sanitize_input($input['role'] ?? 'User');
$phone = sanitize_input($input['phone'] ?? '');

// Validar campos requeridos
if (empty($username)) {
    $errors[] = 'Username is required';
} elseif (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
    $errors[] = 'Username must be 3-20 characters, alphanumeric and underscore only';
}

if (empty($password)) {
    $errors[] = 'Password is required';
} else {
    $password_strength = validate_password_strength($password);
    if (!$password_strength['valid']) {
        $errors = array_merge($errors, $password_strength['errors']);
    }
}

if (empty($email)) {
    $errors[] = 'Email is required';
} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'Invalid email format';
}

if (empty($full_name)) {
    $errors[] = 'Full name is required';
}

// Validar rol
$valid_roles = ['User', 'SupportAdmin', 'Admin', 'SuperUser'];
if (!in_array($role, $valid_roles)) {
    $errors[] = 'Invalid role';
}

// Admins no pueden crear SuperUsers
if ($user['role'] === 'Admin' && $role === 'SuperUser') {
    $errors[] = 'Admins cannot create SuperUser accounts';
}

if (!empty($errors)) {
    http_response_code(400);
    echo json_encode(['error' => 'Validation failed', 'errors' => $errors]);
    exit;
}

try {
    $db = Database::getInstance()->getConnection();
    
    // Verificar username único
    $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
    $stmt->execute([$username]);
    if ($stmt->fetch()) {
        http_response_code(409);
        echo json_encode(['error' => 'Username already exists']);
        exit;
    }
    
    // Verificar email único
    $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        http_response_code(409);
        echo json_encode(['error' => 'Email already in use']);
        exit;
    }
    
    // Hashear password
    $password_hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    
    // Insertar usuario
    $stmt = $db->prepare("
        INSERT INTO users (username, password, email, full_name, role, phone, status, created_at, created_by) 
        VALUES (?, ?, ?, ?, ?, ?, 'active', NOW(), ?)
    ");
    
    $stmt->execute([
        $username,
        $password_hash,
        $email,
        $full_name,
        $role,
        $phone ?: null,
        $user['id']
    ]);
    
    $user_id = $db->lastInsertId();
    
    // Log de actividad
    log_activity('user_created', $user['id'], [
        'new_user_id' => $user_id,
        'new_username' => $username,
        'new_role' => $role
    ]);
    
    // Log de seguridad
    security_log('user_created', $user['id'], [
        'new_user' => $username,
        'role' => $role
    ]);
    
    echo json_encode([
        'success' => true,
        'user_id' => (int)$user_id,
        'message' => 'User created successfully'
    ]);
    
} catch (Exception $e) {
    error_log("Add user error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Failed to create user',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
    ]);
}
