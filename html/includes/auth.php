<?php
/**
 * SKYN3T - Sistema de Control de Acceso
 * Archivo: includes/auth.php
 * Descripción: Sistema de autenticación y autorización - VERSIÓN CORREGIDA
 * Versión: 2.0.1
 * 
 * FIXES APLICADOS:
 * - Renombrado get_current_user() a get_authenticated_user() para evitar conflicto con función nativa PHP
 * - Mejorado manejo de sesiones y tokens
 */

if (!defined('DB_CONFIG_LOADED')) {
    require_once __DIR__ . '/config.php';
}

require_once __DIR__ . '/database.php';
require_once __DIR__ . '/session.php';

class Auth {
    private $db;
    private $sessionManager;
    
    public function __construct() {
        $this->db = Database::getInstance()->getConnection();
        $this->sessionManager = SessionManager::getInstance();
    }
    
    /**
     * Autenticar usuario con username y password
     * 
     * @param string $username
     * @param string $password
     * @return array|false Usuario autenticado o false si falla
     */
    public function authenticate($username, $password) {
        try {
            // Buscar usuario
            $stmt = $this->db->prepare("
                SELECT id, username, password, role, is_active 
                FROM " . USERS_TABLE . " 
                WHERE username = ? 
                LIMIT 1
            ");
            
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user || !password_verify($password, $user['password'])) {
                return false;
            }
            
            if (!$user['is_active']) {
                throw new Exception('User account is inactive');
            }
            
            // Eliminar el campo password antes de retornar
            unset($user['password']);
            
            return $user;
            
        } catch (Exception $e) {
            error_log("Authentication error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Verificar si el usuario actual está autenticado
     * 
     * @return bool
     */
    public function isAuthenticated() {
        $this->sessionManager->startSession();
        return $this->sessionManager->validateSession();
    }
    
    /**
     * Verificar si el usuario tiene un rol específico
     * 
     * @param string|array $roles Rol o array de roles permitidos
     * @return bool
     */
    public function hasRole($roles) {
        if (!$this->isAuthenticated()) {
            return false;
        }
        
        $userRole = $_SESSION['role'] ?? null;
        
        if (!$userRole) {
            return false;
        }
        
        if (is_string($roles)) {
            return $userRole === $roles;
        }
        
        if (is_array($roles)) {
            return in_array($userRole, $roles);
        }
        
        return false;
    }
    
    /**
     * Verificar si el usuario tiene un permiso específico
     * 
     * @param string $permission
     * @return bool
     */
    public function hasPermission($permission) {
        if (!$this->isAuthenticated()) {
            return false;
        }
        
        $role = $_SESSION['role'] ?? null;
        
        if (!$role) {
            return false;
        }
        
        // Definir permisos por rol
        $rolePermissions = [
            'SuperUser' => [
                'system.config',
                'users.view', 'users.create', 'users.edit', 'users.delete',
                'devices.view', 'devices.create', 'devices.edit', 'devices.delete',
                'relay.control', 'relay.override',
                'logs.view', 'logs.export',
                'api.full_access'
            ],
            'Admin' => [
                'users.view', 'users.create', 'users.edit',
                'devices.view', 'devices.create', 'devices.edit', 'devices.delete',
                'relay.control',
                'logs.view', 'logs.export',
                'api.full_access'
            ],
            'SupportAdmin' => [
                'users.view',
                'devices.view', 'devices.edit',
                'relay.control',
                'logs.view',
                'api.limited_access'
            ],
            'User' => [
                'devices.view',
                'relay.control',
                'api.limited_access'
            ]
        ];
        
        $permissions = $rolePermissions[$role] ?? [];
        
        return in_array($permission, $permissions);
    }
    
    /**
     * Obtener nivel de acceso del rol
     * 
     * @param string $role
     * @return int
     */
    public function getRoleLevel($role) {
        $levels = [
            'SuperUser' => 4,
            'Admin' => 3,
            'SupportAdmin' => 2,
            'User' => 1
        ];
        
        return $levels[$role] ?? 0;
    }
    
    /**
     * Verificar si el usuario actual tiene un nivel de acceso mínimo
     * 
     * @param int $minLevel
     * @return bool
     */
    public function hasMinimumLevel($minLevel) {
        if (!$this->isAuthenticated()) {
            return false;
        }
        
        $role = $_SESSION['role'] ?? null;
        
        if (!$role) {
            return false;
        }
        
        return $this->getRoleLevel($role) >= $minLevel;
    }
    
    /**
     * Requerir autenticación - redirigir si no está autenticado
     * 
     * @param string $redirectTo URL de redirección (por defecto login)
     */
    public function requireAuth($redirectTo = '/login/') {
        if (!$this->isAuthenticated()) {
            header("Location: $redirectTo");
            exit;
        }
    }
    
    /**
     * Requerir un rol específico - redirigir si no tiene el rol
     * 
     * @param string|array $roles
     * @param string $redirectTo
     */
    public function requireRole($roles, $redirectTo = '/dashboard/') {
        $this->requireAuth();
        
        if (!$this->hasRole($roles)) {
            header("Location: $redirectTo");
            exit;
        }
    }
    
    /**
     * Requerir un permiso específico
     * 
     * @param string $permission
     * @param string $redirectTo
     */
    public function requirePermission($permission, $redirectTo = '/dashboard/') {
        $this->requireAuth();
        
        if (!$this->hasPermission($permission)) {
            header("Location: $redirectTo");
            exit;
        }
    }
    
    /**
     * Verificar token de API
     * 
     * @param string $token
     * @return array|false Usuario si el token es válido
     */
    public function validateApiToken($token) {
        try {
            // Buscar sesión activa con este token
            $stmt = $this->db->prepare("
                SELECT s.*, u.id as user_id, u.username, u.role, u.is_active
                FROM " . SESSIONS_TABLE . " s
                JOIN " . USERS_TABLE . " u ON s.user_id = u.id
                WHERE s.session_token = ?
                AND s.is_active = 1
                AND s.expires_at > NOW()
                LIMIT 1
            ");
            
            $stmt->execute([$token]);
            $session = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$session) {
                return false;
            }
            
            if (!$session['is_active']) {
                return false;
            }
            
            // Actualizar última actividad
            $stmt = $this->db->prepare("
                UPDATE " . SESSIONS_TABLE . "
                SET last_activity = NOW()
                WHERE session_token = ?
            ");
            $stmt->execute([$token]);
            
            return [
                'id' => $session['user_id'],
                'username' => $session['username'],
                'role' => $session['role'],
                'session_id' => $session['session_id']
            ];
            
        } catch (Exception $e) {
            error_log("API token validation error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Validar request de API
     * 
     * @return array|false Usuario autenticado o false
     */
    public function validateRequest() {
        // Verificar header Authorization
        $headers = getallheaders();
        $authHeader = $headers['Authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        
        if (empty($authHeader)) {
            return false;
        }
        
        // Extraer token Bearer
        if (!preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            return false;
        }
        
        $token = $matches[1];
        
        if (empty($token)) {
            return false;
        }
        
        // Validar token
        return $this->validateApiToken($token);
    }
    
    /**
     * Registrar intento de acceso fallido
     * 
     * @param string $username
     * @param string $reason
     * @param string $ip
     */
    public function logFailedAttempt($username, $reason, $ip = null) {
        try {
            $ip = $ip ?: ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
            
            $stmt = $this->db->prepare("
                INSERT INTO " . ACCESS_LOG_TABLE . "
                (user_id, username, action, details, ip_address, user_agent)
                VALUES (NULL, ?, 'auth_failed', ?, ?, ?)
            ");
            
            $details = json_encode([
                'reason' => $reason,
                'timestamp' => date('Y-m-d H:i:s')
            ]);
            
            $stmt->execute([$username, $details, $ip, $userAgent]);
            
        } catch (Exception $e) {
            error_log("Failed to log auth attempt: " . $e->getMessage());
        }
    }
    
    /**
     * Verificar si una IP está bloqueada por intentos fallidos
     * 
     * @param string $ip
     * @return bool
     */
    public function isIpBlocked($ip) {
        try {
            // Contar intentos fallidos en los últimos 15 minutos
            $stmt = $this->db->prepare("
                SELECT COUNT(*) as attempts
                FROM " . ACCESS_LOG_TABLE . "
                WHERE ip_address = ?
                AND action IN ('auth_failed', 'login_failed')
                AND timestamp > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
            ");
            
            $stmt->execute([$ip]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return ($result['attempts'] >= 5);
            
        } catch (Exception $e) {
            error_log("IP block check error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Cerrar sesión del usuario actual
     */
    public function logout() {
        $this->sessionManager->destroySession();
    }
    
    /**
     * Cambiar contraseña del usuario
     * 
     * @param int $userId
     * @param string $currentPassword
     * @param string $newPassword
     * @return bool
     */
    public function changePassword($userId, $currentPassword, $newPassword) {
        try {
            // Verificar contraseña actual
            $stmt = $this->db->prepare("
                SELECT password 
                FROM " . USERS_TABLE . " 
                WHERE id = ?
            ");
            
            $stmt->execute([$userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user || !password_verify($currentPassword, $user['password'])) {
                return false;
            }
            
            // Actualizar contraseña
            $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
            
            $stmt = $this->db->prepare("
                UPDATE " . USERS_TABLE . "
                SET password = ?,
                    updated_at = NOW()
                WHERE id = ?
            ");
            
            return $stmt->execute([$newHash, $userId]);
            
        } catch (Exception $e) {
            error_log("Password change error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Generar token de recuperación de contraseña
     * 
     * @param string $email
     * @return string|false Token o false si falla
     */
    public function generatePasswordResetToken($email) {
        try {
            // Buscar usuario por email
            $stmt = $this->db->prepare("
                SELECT id 
                FROM " . USERS_TABLE . " 
                WHERE email = ? 
                AND is_active = 1
            ");
            
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user) {
                return false;
            }
            
            // Generar token único
            $token = bin2hex(random_bytes(32));
            $expires = date('Y-m-d H:i:s', strtotime('+1 hour'));
            
            // Guardar token
            $stmt = $this->db->prepare("
                INSERT INTO password_resets 
                (user_id, token, expires_at) 
                VALUES (?, ?, ?)
                ON DUPLICATE KEY UPDATE 
                token = VALUES(token),
                expires_at = VALUES(expires_at)
            ");
            
            $stmt->execute([$user['id'], $token, $expires]);
            
            return $token;
            
        } catch (Exception $e) {
            error_log("Password reset token error: " . $e->getMessage());
            return false;
        }
    }
}

// Funciones helper globales

/**
 * Verificar si el usuario está autenticado
 * 
 * @return bool
 */
function is_authenticated() {
    $auth = new Auth();
    return $auth->isAuthenticated();
}

/**
 * Obtener usuario autenticado actual (RENOMBRADA de get_current_user)
 * 
 * @return array|null
 */
function get_authenticated_user() {
    if (!is_authenticated()) {
        return null;
    }
    
    return [
        'id' => $_SESSION['user_id'] ?? null,
        'username' => $_SESSION['username'] ?? null,
        'role' => $_SESSION['role'] ?? null
    ];
}

/**
 * Verificar si el usuario tiene un rol específico
 * 
 * @param string|array $roles
 * @return bool
 */
function user_has_role($roles) {
    $auth = new Auth();
    return $auth->hasRole($roles);
}

/**
 * Verificar si el usuario tiene un permiso específico
 * 
 * @param string $permission
 * @return bool
 */
function user_can($permission) {
    $auth = new Auth();
    return $auth->hasPermission($permission);
}

/**
 * Requerir autenticación
 * 
 * @param string $redirectTo
 */
function require_auth($redirectTo = '/login/') {
    $auth = new Auth();
    $auth->requireAuth($redirectTo);
}

/**
 * Requerir rol específico
 * 
 * @param string|array $roles
 * @param string $redirectTo
 */
function require_role($roles, $redirectTo = '/dashboard/') {
    $auth = new Auth();
    $auth->requireRole($roles, $redirectTo);
}

/**
 * Middleware para proteger páginas
 * Usar al inicio de páginas protegidas
 */
function auth_middleware() {
    $auth = new Auth();
    
    if (!$auth->isAuthenticated()) {
        // Si es una petición AJAX, devolver JSON
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            header('Content-Type: application/json');
            http_response_code(401);
            echo json_encode([
                'success' => false,
                'error' => 'Authentication required'
            ]);
            exit;
        }
        
        // Si no, redirigir al login
        header('Location: /login/');
        exit;
    }
}
