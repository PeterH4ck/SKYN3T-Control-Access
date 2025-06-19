<?php
/**
 * ARCHIVO CONVERTIDO DE SQLite A MySQL
 * Sistema de Control de Relé - Login con Control de Acceso por Roles
 * Ubicación: /login/login.php
 * Versión: 2.0 - Actualizada con Dashboard y Control de Roles
 */

session_start();
require_once __DIR__ . '/../includes/database_mysql.php';

// Configuración de seguridad
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_DURATION', 300); // 5 minutos
define('SESSION_TIMEOUT', 3600); // 1 hora

// Función para verificar si la IP está bloqueada
function isIPLocked($ip) {
    $db = Database::getInstance();
    
    $result = $db->queryOne(
        "SELECT COUNT(*) as attempts, 
                MAX(timestamp) as last_attempt
         FROM access_log 
         WHERE ip_address = :ip 
           AND action = 'login_failed' 
           AND timestamp > DATE_SUB(NOW(), INTERVAL :duration SECOND)",
        [
            'ip' => $ip,
            'duration' => LOCKOUT_DURATION
        ]
    );
    
    return $result['attempts'] >= MAX_LOGIN_ATTEMPTS;
}

// Función para verificar timeout de sesión
function checkSessionTimeout() {
    if (isset($_SESSION['login_time'])) {
        $sessionAge = time() - $_SESSION['login_time'];
        if ($sessionAge > SESSION_TIMEOUT) {
            // Sesión expirada
            session_unset();
            session_destroy();
            return false;
        }
        // Renovar tiempo de sesión
        $_SESSION['login_time'] = time();
    }
    return true;
}

// Función para determinar redirección según rol
function getRedirectByRole($role) {
    switch($role) {
        case 'superUser':
        case 'SupportUser':
        case 'Admin':
            return '/rele/dashboard.html';
        case 'User':
        default:
            return '/rele/index_rele.html';
    }
}

// Función principal de autenticación
function authenticateUser($username, $password, $remember = false) {
    $db = Database::getInstance();
    $ip = $_SERVER['REMOTE_ADDR'];
    
    try {
        // Verificar si la IP está bloqueada
        if (isIPLocked($ip)) {
            return [
                'success' => false, 
                'message' => 'Demasiados intentos fallidos. Intente más tarde.',
                'locked' => true
            ];
        }
        
        // Buscar usuario
        $user = $db->queryOne(
            "SELECT u.*, 
                    (u.locked_until > NOW()) as is_locked,
                    u.last_login,
                    u.failed_attempts
             FROM usuarios u 
             WHERE u.username = :username 
               AND u.is_active = 1",
            ['username' => $username]
        );
        
        if (!$user) {
            // Registrar intento fallido
            logLoginAttempt($username, 'login_failed', $ip, 'Usuario no encontrado');
            return [
                'success' => false, 
                'message' => 'Usuario o contraseña incorrectos'
            ];
        }
        
        // Verificar si el usuario está bloqueado
        if ($user['is_locked']) {
            logLoginAttempt($username, 'login_blocked', $ip, 'Usuario bloqueado');
            return [
                'success' => false, 
                'message' => 'Usuario bloqueado temporalmente. Contacte al administrador.'
            ];
        }
        
        // Verificar contraseña
        if (!password_verify($password, $user['password'])) {
            // Incrementar intentos fallidos
            incrementFailedAttempts($user['id']);
            logLoginAttempt($username, 'login_failed', $ip, 'Contraseña incorrecta');
            
            return [
                'success' => false, 
                'message' => 'Usuario o contraseña incorrectos'
            ];
        }
        
        // Login exitoso - Iniciar transacción
        $db->beginTransaction();
        
        try {
            // Actualizar último login y resetear intentos
            $db->execute(
                "UPDATE usuarios 
                 SET last_login = NOW(), 
                     failed_attempts = 0,
                     locked_until = NULL,
                     login_count = COALESCE(login_count, 0) + 1
                 WHERE id = :id",
                ['id' => $user['id']]
            );
            
            // Registrar acceso exitoso
            logLoginAttempt($username, 'login_success', $ip, 'Login exitoso');
            
            // Limpiar datos sensibles del objeto user
            unset($user['password']);
            unset($user['is_locked']);
            
            // Establecer sesión segura
            session_regenerate_id(true); // Regenerar ID de sesión por seguridad
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['login_time'] = time();
            $_SESSION['ip'] = $ip;
            $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
            
            // Generar token CSRF
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            
            // Configurar cookie "Recuérdame" si se solicitó
            if ($remember) {
                $remember_token = bin2hex(random_bytes(32));
                $expire_time = time() + (30 * 24 * 60 * 60); // 30 días
                
                // Guardar token en base de datos
                $db->execute(
                    "UPDATE usuarios 
                     SET remember_token = :token,
                         remember_token_expires = FROM_UNIXTIME(:expires)
                     WHERE id = :id",
                    [
                        'token' => password_hash($remember_token, PASSWORD_DEFAULT),
                        'expires' => $expire_time,
                        'id' => $user['id']
                    ]
                );
                
                // Establecer cookie
                setcookie(
                    'remember_token', 
                    $user['id'] . ':' . $remember_token, 
                    $expire_time, 
                    '/', 
                    '', 
                    true, // Secure (solo HTTPS en producción)
                    true  // HttpOnly
                );
            }
            
            $db->commit();
            
            // Determinar redirección según rol
            $redirect_url = getRedirectByRole($user['role']);
            
            return [
                'success' => true, 
                'user' => $user,
                'redirect' => $redirect_url,
                'message' => 'Autenticación exitosa. Redirigiendo...',
                'role' => $user['role']
            ];
            
        } catch (Exception $e) {
            $db->rollback();
            throw $e;
        }
        
    } catch (Exception $e) {
        error_log("Error en authenticateUser: " . $e->getMessage());
        logLoginAttempt($username, 'login_error', $ip, 'Error del sistema: ' . $e->getMessage());
        return [
            'success' => false, 
            'message' => 'Error del sistema. Intente más tarde.'
        ];
    }
}

// Función para incrementar intentos fallidos
function incrementFailedAttempts($userId) {
    $db = Database::getInstance();
    
    $db->execute(
        "UPDATE usuarios 
         SET failed_attempts = failed_attempts + 1,
             locked_until = CASE 
                WHEN failed_attempts >= :max_attempts - 1 
                THEN DATE_ADD(NOW(), INTERVAL :lockout SECOND)
                ELSE locked_until 
             END
         WHERE id = :id",
        [
            'id' => $userId,
            'max_attempts' => MAX_LOGIN_ATTEMPTS,
            'lockout' => LOCKOUT_DURATION
        ]
    );
}

// Función para registrar intentos de login
function logLoginAttempt($username, $action, $ip, $details = '') {
    $db = Database::getInstance();
    
    try {
        $db->execute(
            "INSERT INTO access_log (username, action, ip_address, user_agent, response_code, details, timestamp)
             VALUES (:username, :action, :ip, :user_agent, :code, :details, NOW())",
            [
                'username' => $username,
                'action' => $action,
                'ip' => $ip,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
                'code' => ($action === 'login_success') ? 200 : 401,
                'details' => $details
            ]
        );
    } catch (Exception $e) {
        error_log("Error logging access attempt: " . $e->getMessage());
    }
}

// Función para verificar token "Recuérdame"
function checkRememberToken() {
    if (!isset($_COOKIE['remember_token'])) {
        return false;
    }
    
    $token_parts = explode(':', $_COOKIE['remember_token'], 2);
    if (count($token_parts) !== 2) {
        return false;
    }
    
    $user_id = $token_parts[0];
    $token = $token_parts[1];
    
    $db = Database::getInstance();
    
    try {
        $user = $db->queryOne(
            "SELECT id, username, role, remember_token, remember_token_expires
             FROM usuarios 
             WHERE id = :id 
               AND is_active = 1
               AND remember_token IS NOT NULL
               AND remember_token_expires > NOW()",
            ['id' => $user_id]
        );
        
        if ($user && password_verify($token, $user['remember_token'])) {
            // Auto login
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['login_time'] = time();
            $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
            $_SESSION['auto_login'] = true;
            
            // Generar nuevo token CSRF
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            
            logLoginAttempt($user['username'], 'auto_login', $_SERVER['REMOTE_ADDR'], 'Remember token');
            
            return $user;
        }
    } catch (Exception $e) {
        error_log("Error checking remember token: " . $e->getMessage());
    }
    
    // Limpiar cookie inválida
    setcookie('remember_token', '', time() - 3600, '/');
    return false;
}

// Verificar si ya hay una sesión activa o token válido
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Verificar sesión existente
    if (isset($_SESSION['user_id']) && checkSessionTimeout()) {
        // Verificar que la IP coincida por seguridad
        if ($_SESSION['ip'] === $_SERVER['REMOTE_ADDR']) {
            $redirect_url = getRedirectByRole($_SESSION['role']);
            header("Location: $redirect_url");
            exit;
        } else {
            // IP diferente - posible secuestro de sesión
            session_unset();
            session_destroy();
        }
    } else {
        // Verificar token "Recuérdame"
        $remembered_user = checkRememberToken();
        if ($remembered_user) {
            $redirect_url = getRedirectByRole($remembered_user['role']);
            header("Location: $redirect_url");
            exit;
        }
    }
}

// Procesar solicitud POST (login)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    // Verificar token CSRF (si existe en la sesión)
    if (isset($_SESSION['csrf_token']) && 
        (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token'])) {
        http_response_code(403);
        echo json_encode([
            'success' => false, 
            'message' => 'Token CSRF inválido. Recarga la página.'
        ]);
        exit;
    }
    
    // Validar entrada
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $password = $_POST['password'] ?? '';
    $remember = filter_input(INPUT_POST, 'remember', FILTER_VALIDATE_BOOLEAN);
    
    if (empty($username) || empty($password)) {
        http_response_code(400);
        echo json_encode([
            'success' => false, 
            'message' => 'Usuario y contraseña son requeridos'
        ]);
        exit;
    }
    
    // Limitar longitud para prevenir ataques
    if (strlen($username) > 50 || strlen($password) > 255) {
        http_response_code(400);
        echo json_encode([
            'success' => false, 
            'message' => 'Datos inválidos - longitud excedida'
        ]);
        exit;
    }
    
    // Verificar rate limiting por IP
    if (isIPLocked($_SERVER['REMOTE_ADDR'])) {
        http_response_code(429);
        echo json_encode([
            'success' => false, 
            'message' => 'Demasiados intentos fallidos. Intente más tarde.',
            'retry_after' => LOCKOUT_DURATION
        ]);
        exit;
    }
    
    // Intentar autenticación
    $result = authenticateUser($username, $password, $remember);
    
    // Establecer código de respuesta HTTP
    if ($result['success']) {
        http_response_code(200);
    } else {
        if (isset($result['locked']) && $result['locked']) {
            http_response_code(429); // Too Many Requests
        } else {
            http_response_code(401); // Unauthorized
        }
    }
    
    echo json_encode($result);
    exit;
}

// Para solicitudes GET con parámetro stats (solo en desarrollo)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && 
    isset($_GET['stats']) && 
    $_SERVER['SERVER_NAME'] === 'localhost') {
    
    $db = Database::getInstance();
    
    $stats = [
        'total_users' => $db->queryOne("SELECT COUNT(*) as total FROM usuarios")['total'],
        'active_users' => $db->queryOne("SELECT COUNT(*) as total FROM usuarios WHERE is_active = 1")['total'],
        'locked_users' => $db->queryOne("SELECT COUNT(*) as total FROM usuarios WHERE locked_until > NOW()")['total'],
        'admin_users' => $db->queryOne("SELECT COUNT(*) as total FROM usuarios WHERE role IN ('Admin', 'superUser')")['total'],
        'recent_logins' => $db->query(
            "SELECT username, action, ip_address, timestamp 
             FROM access_log 
             WHERE action IN ('login_success', 'login_failed', 'auto_login')
             ORDER BY timestamp DESC 
             LIMIT 10"
        ),
        'roles_distribution' => $db->query(
            "SELECT role, COUNT(*) as count 
             FROM usuarios 
             WHERE is_active = 1 
             GROUP BY role"
        )
    ];
    
    header('Content-Type: application/json');
    echo json_encode($stats, JSON_PRETTY_PRINT);
    exit;
}

// Endpoint para verificar estado de sesión (AJAX)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && 
    isset($_GET['check_session'])) {
    
    header('Content-Type: application/json');
    
    if (isset($_SESSION['user_id']) && checkSessionTimeout()) {
        echo json_encode([
            'authenticated' => true,
            'username' => $_SESSION['username'],
            'role' => $_SESSION['role'],
            'redirect' => getRedirectByRole($_SESSION['role'])
        ]);
    } else {
        echo json_encode(['authenticated' => false]);
    }
    exit;
}

// Respuesta por defecto para métodos no permitidos
http_response_code(405);
header('Content-Type: application/json');
echo json_encode([
    'error' => 'Method not allowed',
    'allowed_methods' => ['GET', 'POST']
]);
?>