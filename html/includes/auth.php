<?php
/**
 * Archivo: /var/www/html/includes/auth.php
 * Sistema de autenticación robusto para SKYN3T
 */

// Evitar acceso directo
if (!defined('SKYN3T_SYSTEM')) {
    die('Access denied');
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/security.php';

class Auth {
    private $db;
    private static $instance = null;
    
    /**
     * Constructor privado para Singleton
     */
    private function __construct() {
        $this->db = Database::getInstance();
    }
    
    /**
     * Obtener instancia única (Singleton)
     */
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Autenticar usuario con username y password
     */
    public function authenticate($username, $password) {
        try {
            // Validar entrada
            if (empty($username) || empty($password)) {
                return [
                    'success' => false,
                    'message' => 'Usuario y contraseña requeridos',
                    'error_code' => 'EMPTY_CREDENTIALS'
                ];
            }
            
            // Limpiar username
            $username = trim($username);
            
            // Verificar rate limiting
            if (!$this->checkRateLimit($username)) {
                return [
                    'success' => false,
                    'message' => 'Demasiados intentos. Intente más tarde.',
                    'error_code' => 'RATE_LIMITED'
                ];
            }
            
            // Obtener usuario de la base de datos
            $user = $this->getUserByUsername($username);
            
            if (!$user) {
                $this->logFailedAttempt($username, null, 'user_not_found');
                return [
                    'success' => false,
                    'message' => 'Usuario o contraseña incorrectos',
                    'error_code' => 'INVALID_CREDENTIALS'
                ];
            }
            
            // Verificar si el usuario está activo
            if (!$user['active'] || !$user['is_active']) {
                $this->logFailedAttempt($username, $user['id'], 'user_inactive');
                return [
                    'success' => false,
                    'message' => 'Usuario desactivado',
                    'error_code' => 'USER_INACTIVE'
                ];
            }
            
            // Verificar si el usuario está bloqueado
            if ($this->isUserLocked($user)) {
                $this->logFailedAttempt($username, $user['id'], 'user_locked');
                return [
                    'success' => false,
                    'message' => 'Usuario temporalmente bloqueado',
                    'error_code' => 'USER_LOCKED'
                ];
            }
            
            // Verificar contraseña
            if (!$this->verifyPassword($password, $user['password'])) {
                $this->incrementFailedAttempts($user['id']);
                $this->logFailedAttempt($username, $user['id'], 'wrong_password');
                return [
                    'success' => false,
                    'message' => 'Usuario o contraseña incorrectos',
                    'error_code' => 'INVALID_CREDENTIALS'
                ];
            }
            
            // Autenticación exitosa
            $this->resetFailedAttempts($user['id']);
            $this->updateLastLogin($user['id']);
            $this->logSuccessfulLogin($user);
            
            return [
                'success' => true,
                'user' => $this->sanitizeUserData($user),
                'message' => 'Autenticación exitosa'
            ];
            
        } catch (Exception $e) {
            error_log("Error en autenticación: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Error del sistema',
                'error_code' => 'SYSTEM_ERROR'
            ];
        }
    }
    
    /**
     * Verificar token de sesión
     */
    public function verifySession($token) {
        try {
            if (empty($token)) {
                return [
                    'valid' => false,
                    'message' => 'Token no proporcionado'
                ];
            }
            
            // Limpiar sesiones expiradas
            $this->cleanExpiredSessions();
            
            // Buscar sesión activa
            $session = $this->db->fetch("
                SELECT s.*, u.username, u.name, u.email, u.role, u.privileges, u.active, u.is_active
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.session_token = ? AND s.expires_at > NOW()
            ", [$token]);
            
            if (!$session) {
                return [
                    'valid' => false,
                    'message' => 'Sesión inválida o expirada'
                ];
            }
            
            // Verificar que el usuario sigue activo
            if (!$session['active'] || !$session['is_active']) {
                $this->destroySession($token);
                return [
                    'valid' => false,
                    'message' => 'Usuario desactivado'
                ];
            }
            
            // Extender sesión
            $this->extendSession($token);
            
            return [
                'valid' => true,
                'user' => $this->sanitizeUserData($session),
                'session' => [
                    'token' => $token,
                    'expires_at' => date('Y-m-d H:i:s', time() + SESSION_LIFETIME),
                    'created_at' => $session['created_at']
                ]
            ];
            
        } catch (Exception $e) {
            error_log("Error verificando sesión: " . $e->getMessage());
            return [
                'valid' => false,
                'message' => 'Error del sistema'
            ];
        }
    }
    
    /**
     * Crear nueva sesión
     */
    public function createSession($userId, $rememberMe = false) {
        try {
            // Limpiar sesiones anteriores del usuario
            $this->db->executeQuery(
                "DELETE FROM sessions WHERE user_id = ?",
                [$userId]
            );
            
            // Generar token único
            $token = Security::generateSecureToken(TOKEN_LENGTH);
            
            // Calcular tiempo de expiración
            $lifetime = $rememberMe ? SESSION_REMEMBER_LIFETIME : SESSION_LIFETIME;
            $expiresAt = date('Y-m-d H:i:s', time() + $lifetime);
            
            // Obtener información de la conexión
            $ip = Security::getClientIP();
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            
            // Insertar nueva sesión
            $this->db->executeQuery("
                INSERT INTO sessions (user_id, session_token, expires_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
            ", [$userId, $token, $expiresAt, $ip, $userAgent]);
            
            return [
                'success' => true,
                'token' => $token,
                'expires_at' => $expiresAt
            ];
            
        } catch (Exception $e) {
            error_log("Error creando sesión: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Error creando sesión'
            ];
        }
    }
    
    /**
     * Destruir sesión
     */
    public function destroySession($token) {
        try {
            $this->db->executeQuery(
                "DELETE FROM sessions WHERE session_token = ?",
                [$token]
            );
            return true;
        } catch (Exception $e) {
            error_log("Error destruyendo sesión: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Destruir todas las sesiones de un usuario
     */
    public function destroyAllUserSessions($userId) {
        try {
            $this->db->executeQuery(
                "DELETE FROM sessions WHERE user_id = ?",
                [$userId]
            );
            return true;
        } catch (Exception $e) {
            error_log("Error destruyendo sesiones del usuario: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Verificar permisos de usuario
     */
    public function hasPermission($user, $permission) {
        // SuperUser tiene todos los permisos
        if ($user['role'] === ROLE_SUPER_USER) {
            return true;
        }
        
        // Decodificar privilegios del usuario
        $privileges = [];
        if (!empty($user['privileges'])) {
            $privileges = json_decode($user['privileges'], true) ?: [];
        }
        
        // Verificar permiso específico
        if (isset($privileges[$permission]) && $privileges[$permission]) {
            return true;
        }
        
        // Verificar permiso 'all'
        if (isset($privileges['all']) && $privileges['all']) {
            return true;
        }
        
        // Verificar permisos por defecto del rol
        return hasPermission($user['role'], $permission);
    }
    
    /**
     * Verificar si el usuario tiene rol suficiente
     */
    public function hasRole($user, $requiredRole) {
        return isRoleHigherThan($user['role'], $requiredRole) || $user['role'] === $requiredRole;
    }
    
    /**
     * Middleware de autenticación para páginas protegidas
     */
    public function requireAuth($requiredRole = null, $permission = null) {
        // Verificar sesión
        $token = $this->getTokenFromRequest();
        
        if (!$token) {
            $this->redirectToLogin('Token no encontrado');
            return false;
        }
        
        $sessionResult = $this->verifySession($token);
        
        if (!$sessionResult['valid']) {
            $this->redirectToLogin($sessionResult['message']);
            return false;
        }
        
        $user = $sessionResult['user'];
        
        // Verificar rol requerido
        if ($requiredRole && !$this->hasRole($user, $requiredRole)) {
            $this->redirectToError('Permisos insuficientes');
            return false;
        }
        
        // Verificar permiso específico
        if ($permission && !$this->hasPermission($user, $permission)) {
            $this->redirectToError('Permiso denegado');
            return false;
        }
        
        // Guardar datos del usuario en variable global
        $GLOBALS['current_user'] = $user;
        $GLOBALS['current_session'] = $sessionResult['session'];
        
        return $user;
    }
    
    /**
     * Obtener usuario actual desde la sesión
     */
    public function getCurrentUser() {
        return $GLOBALS['current_user'] ?? null;
    }
    
    /**
     * Cambiar contraseña de usuario
     */
    public function changePassword($userId, $newPassword, $currentPassword = null) {
        try {
            // Obtener usuario actual
            $user = $this->db->fetch("SELECT * FROM users WHERE id = ?", [$userId]);
            
            if (!$user) {
                return [
                    'success' => false,
                    'message' => 'Usuario no encontrado'
                ];
            }
            
            // Verificar contraseña actual si se proporciona
            if ($currentPassword && !$this->verifyPassword($currentPassword, $user['password'])) {
                return [
                    'success' => false,
                    'message' => 'Contraseña actual incorrecta'
                ];
            }
            
            // Validar nueva contraseña
            $passwordValidation = Security::validatePassword($newPassword);
            if (!$passwordValidation['valid']) {
                return [
                    'success' => false,
                    'message' => $passwordValidation['message']
                ];
            }
            
            // Hashear nueva contraseña
            $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
            
            // Actualizar contraseña
            $this->db->executeQuery(
                "UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?",
                [$hashedPassword, $userId]
            );
            
            // Destruir todas las sesiones del usuario (forzar re-login)
            $this->destroyAllUserSessions($userId);
            
            // Log del cambio
            $this->logActivity($userId, 'password_changed');
            
            return [
                'success' => true,
                'message' => 'Contraseña actualizada correctamente'
            ];
            
        } catch (Exception $e) {
            error_log("Error cambiando contraseña: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Error del sistema'
            ];
        }
    }
    
    // ================================================
    // MÉTODOS PRIVADOS
    // ================================================
    
    private function getUserByUsername($username) {
        return $this->db->fetch("
            SELECT id, username, password, name, email, role, privileges, 
                   active, is_active, failed_attempts, locked_until, last_login
            FROM users 
            WHERE username = ? 
            LIMIT 1
        ", [$username]);
    }
    
    private function verifyPassword($password, $hash) {
        // Intentar con password_verify primero
        if (password_verify($password, $hash)) {
            return true;
        }
        
        // Fallback para contraseñas en texto plano (compatibilidad)
        return $password === $hash;
    }
    
    private function isUserLocked($user) {
        if (!$user['locked_until']) {
            return false;
        }
        
        return strtotime($user['locked_until']) > time();
    }
    
    private function incrementFailedAttempts($userId) {
        $this->db->executeQuery(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?",
            [$userId]
        );
        
        // Verificar si debe bloquearse
        $user = $this->db->fetch("SELECT failed_attempts FROM users WHERE id = ?", [$userId]);
        
        if ($user && $user['failed_attempts'] >= MAX_LOGIN_ATTEMPTS) {
            $lockUntil = date('Y-m-d H:i:s', time() + LOGIN_LOCKOUT_TIME);
            $this->db->executeQuery(
                "UPDATE users SET locked_until = ? WHERE id = ?",
                [$lockUntil, $userId]
            );
        }
    }
    
    private function resetFailedAttempts($userId) {
        $this->db->executeQuery(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            [$userId]
        );
    }
    
    private function updateLastLogin($userId) {
        $this->db->executeQuery(
            "UPDATE users SET last_login = NOW() WHERE id = ?",
            [$userId]
        );
    }
    
    private function extendSession($token) {
        $newExpires = date('Y-m-d H:i:s', time() + SESSION_LIFETIME);
        $this->db->executeQuery(
            "UPDATE sessions SET expires_at = ? WHERE session_token = ?",
            [$newExpires, $token]
        );
    }
    
    private function cleanExpiredSessions() {
        $this->db->executeQuery("DELETE FROM sessions WHERE expires_at < NOW()");
    }
    
    private function sanitizeUserData($user) {
        $privileges = [];
        if (!empty($user['privileges'])) {
            $privileges = json_decode($user['privileges'], true) ?: [];
        }
        
        return [
            'id' => (int)$user['id'],
            'username' => $user['username'],
            'name' => $user['name'],
            'email' => $user['email'],
            'role' => $user['role'],
            'privileges' => $privileges,
            'active' => (bool)$user['active'],
            'last_login' => $user['last_login']
        ];
    }
    
    private function getTokenFromRequest() {
        // Verificar header Authorization
        $headers = getallheaders();
        if ($headers && isset($headers['Authorization'])) {
            if (preg_match('/Bearer\s+(.*)$/i', $headers['Authorization'], $matches)) {
                return trim($matches[1]);
            }
        }
        
        // Verificar sesión PHP
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        
        return $_SESSION['session_token'] ?? null;
    }
    
    private function redirectToLogin($message = '') {
        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            // Request AJAX
            header('Content-Type: application/json');
            http_response_code(401);
            echo json_encode([
                'authenticated' => false,
                'message' => $message,
                'redirect' => URL_LOGIN
            ]);
            exit;
        } else {
            // Request normal
            header('Location: ' . URL_LOGIN);
            exit;
        }
    }
    
    private function redirectToError($message = '') {
        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            // Request AJAX
            header('Content-Type: application/json');
            http_response_code(403);
            echo json_encode([
                'error' => true,
                'message' => $message
            ]);
            exit;
        } else {
            // Redirigir a página de error o dashboard
            header('Location: ' . URL_DASHBOARD . '?error=' . urlencode($message));
            exit;
        }
    }
    
    private function checkRateLimit($username) {
        // Implementar rate limiting básico
        $ip = Security::getClientIP();
        
        // Contar intentos en la última hora
        $attempts = $this->db->fetch("
            SELECT COUNT(*) as count 
            FROM access_log 
            WHERE (username = ? OR ip_address = ?) 
            AND action LIKE '%failed%' 
            AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        ", [$username, $ip]);
        
        return $attempts['count'] < RATE_LIMIT_REQUESTS;
    }
    
    private function logFailedAttempt($username, $userId, $reason) {
        $this->logActivity($userId, 'login_failed', [
            'username' => $username,
            'reason' => $reason
        ]);
    }
    
    private function logSuccessfulLogin($user) {
        $this->logActivity($user['id'], 'login_success', [
            'username' => $user['username'],
            'role' => $user['role']
        ]);
    }
    
    private function logActivity($userId, $action, $extraData = []) {
        try {
            $ip = Security::getClientIP();
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            
            $this->db->executeQuery("
                INSERT INTO access_log (user_id, username, action, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
            ", [
                $userId,
                $extraData['username'] ?? '',
                $action,
                $ip,
                $userAgent
            ]);
        } catch (Exception $e) {
            error_log("Error registrando actividad: " . $e->getMessage());
        }
    }
}

// ================================================
// FUNCIONES HELPER GLOBALES
// ================================================

/**
 * Obtener instancia de Auth
 */
function getAuth() {
    return Auth::getInstance();
}

/**
 * Verificar si el usuario está autenticado
 */
function isAuthenticated() {
    $auth = getAuth();
    $token = $auth->getTokenFromRequest();
    
    if (!$token) {
        return false;
    }
    
    $result = $auth->verifySession($token);
    return $result['valid'];
}

/**
 * Requerir autenticación en la página actual
 */
function requireAuth($role = null, $permission = null) {
    $auth = getAuth();
    return $auth->requireAuth($role, $permission);
}

/**
 * Obtener usuario actual
 */
function getCurrentUser() {
    return $GLOBALS['current_user'] ?? null;
}

/**
 * Verificar si el usuario actual tiene un permiso
 */
function canUser($permission) {
    $user = getCurrentUser();
    if (!$user) {
        return false;
    }
    
    $auth = getAuth();
    return $auth->hasPermission($user, $permission);
}

/**
 * Verificar si el usuario actual tiene un rol específico
 */
function hasUserRole($role) {
    $user = getCurrentUser();
    if (!$user) {
        return false;
    }
    
    $auth = getAuth();
    return $auth->hasRole($user, $role);
}
?>
