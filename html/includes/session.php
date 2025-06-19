<?php
/**
 * Archivo: /var/www/html/includes/session.php
 * Manejo avanzado de sesiones para SKYN3T
 */

// Evitar acceso directo
if (!defined('SKYN3T_SYSTEM')) {
    die('Access denied');
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/security.php';

class SessionManager {
    private $db;
    private static $instance = null;
    private $sessionStarted = false;
    
    /**
     * Constructor privado para Singleton
     */
    private function __construct() {
        $this->db = Database::getInstance();
        $this->initializeSession();
    }
    
    /**
     * Obtener instancia única
     */
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Inicializar configuración de sesiones
     */
    private function initializeSession() {
        if ($this->sessionStarted) {
            return;
        }
        
        // Configurar parámetros de sesión antes de iniciar
        ini_set('session.use_cookies', 1);
        ini_set('session.use_only_cookies', 1);
        ini_set('session.use_trans_sid', 0);
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', getConfig('SESSION_COOKIE_SECURE', false));
        ini_set('session.cookie_samesite', 'Lax');
        
        // Configurar nombre y parámetros de cookie
        session_name(getConfig('SESSION_COOKIE_NAME', 'SKYN3T_SESSION'));
        
        session_set_cookie_params([
            'lifetime' => getConfig('SESSION_COOKIE_LIFETIME', 0),
            'path' => getConfig('SESSION_COOKIE_PATH', '/'),
            'domain' => getConfig('SESSION_COOKIE_DOMAIN', ''),
            'secure' => getConfig('SESSION_COOKIE_SECURE', false),
            'httponly' => getConfig('SESSION_COOKIE_HTTPONLY', true),
            'samesite' => 'Lax'
        ]);
        
        // Configurar manejador personalizado de sesiones
        session_set_save_handler(
            [$this, 'sessionOpen'],
            [$this, 'sessionClose'],
            [$this, 'sessionRead'],
            [$this, 'sessionWrite'],
            [$this, 'sessionDestroy'],
            [$this, 'sessionGC']
        );
        
        // Iniciar sesión
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
            $this->sessionStarted = true;
            
            // Validar sesión existente
            $this->validateSession();
            
            // Configurar token CSRF si no existe
            if (!isset($_SESSION['csrf_token'])) {
                $_SESSION['csrf_token'] = Security::generateSecureToken(CSRF_TOKEN_LENGTH);
            }
        }
    }
    
    /**
     * Crear nueva sesión de usuario
     */
    public function createUserSession($userId, $userData = [], $rememberMe = false) {
        try {
            // Regenerar ID de sesión para prevenir fijación
            $this->regenerateSessionId();
            
            // Limpiar sesiones anteriores del usuario
            $this->cleanUserSessions($userId);
            
            // Generar token de sesión único
            $sessionToken = Security::generateSecureToken(TOKEN_LENGTH);
            
            // Calcular tiempo de expiración
            $lifetime = $rememberMe ? SESSION_REMEMBER_LIFETIME : SESSION_LIFETIME;
            $expiresAt = date('Y-m-d H:i:s', time() + $lifetime);
            
            // Obtener información de la conexión
            $ip = Security::getClientIP();
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            
            // Guardar sesión en base de datos
            $this->db->executeQuery("
                INSERT INTO sessions (user_id, session_token, expires_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
            ", [$userId, $sessionToken, $expiresAt, $ip, $userAgent]);
            
            // Guardar datos en sesión PHP
            $_SESSION['user_id'] = $userId;
            $_SESSION['session_token'] = $sessionToken;
            $_SESSION['logged_in'] = true;
            $_SESSION['login_time'] = time();
            $_SESSION['last_activity'] = time();
            $_SESSION['remember_me'] = $rememberMe;
            $_SESSION['ip_address'] = $ip;
            $_SESSION['user_agent'] = $userAgent;
            
            // Guardar datos adicionales del usuario
            foreach ($userData as $key => $value) {
                $_SESSION['user_' . $key] = $value;
            }
            
            // Log de creación de sesión
            Security::logSecurityEvent('session_created', [
                'user_id' => $userId,
                'session_token' => substr($sessionToken, 0, 8) . '...',
                'remember_me' => $rememberMe,
                'ip' => $ip
            ], 'INFO');
            
            return [
                'success' => true,
                'session_token' => $sessionToken,
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
     * Validar sesión actual
     */
    public function validateSession() {
        if (!isset($_SESSION['logged_in']) || !$_SESSION['logged_in']) {
            return false;
        }
        
        // Verificar token de sesión
        if (!isset($_SESSION['session_token'])) {
            $this->destroySession();
            return false;
        }
        
        // Verificar en base de datos
        $dbSession = $this->db->fetch("
            SELECT * FROM sessions 
            WHERE session_token = ? AND expires_at > NOW()
        ", [$_SESSION['session_token']]);
        
        if (!$dbSession) {
            $this->destroySession();
            return false;
        }
        
        // Verificar IP y User Agent (opcional, puede ser problemático con proxies)
        $currentIP = Security::getClientIP();
        $currentUA = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        
        if (getConfig('STRICT_SESSION_VALIDATION', false)) {
            if ($dbSession['ip_address'] !== $currentIP || 
                $dbSession['user_agent'] !== $currentUA) {
                
                Security::logSecurityEvent('session_hijack_attempt', [
                    'session_token' => substr($_SESSION['session_token'], 0, 8) . '...',
                    'original_ip' => $dbSession['ip_address'],
                    'current_ip' => $currentIP,
                    'original_ua' => $dbSession['user_agent'],
                    'current_ua' => $currentUA
                ], 'WARNING');
                
                $this->destroySession();
                return false;
            }
        }
        
        // Verificar timeout de inactividad
        $inactivityTimeout = getConfig('SESSION_INACTIVITY_TIMEOUT', 1800); // 30 minutos
        if (isset($_SESSION['last_activity']) && 
            (time() - $_SESSION['last_activity']) > $inactivityTimeout) {
            
            Security::logSecurityEvent('session_timeout', [
                'session_token' => substr($_SESSION['session_token'], 0, 8) . '...',
                'last_activity' => $_SESSION['last_activity'],
                'timeout' => $inactivityTimeout
            ], 'INFO');
            
            $this->destroySession();
            return false;
        }
        
        // Actualizar actividad
        $_SESSION['last_activity'] = time();
        
        // Extender sesión automáticamente
        $this->extendSession();
        
        return true;
    }
    
    /**
     * Extender tiempo de sesión
     */
    public function extendSession($token = null) {
        if (!$token) {
            $token = $_SESSION['session_token'] ?? null;
        }
        
        if (!$token) {
            return false;
        }
        
        try {
            $lifetime = SESSION_LIFETIME;
            if (isset($_SESSION['remember_me']) && $_SESSION['remember_me']) {
                $lifetime = SESSION_REMEMBER_LIFETIME;
            }
            
            $newExpires = date('Y-m-d H:i:s', time() + $lifetime);
            
            $this->db->executeQuery(
                "UPDATE sessions SET expires_at = ? WHERE session_token = ?",
                [$newExpires, $token]
            );
            
            return true;
        } catch (Exception $e) {
            error_log("Error extendiendo sesión: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Destruir sesión actual
     */
    public function destroySession() {
        try {
            // Eliminar de base de datos
            if (isset($_SESSION['session_token'])) {
                $this->db->executeQuery(
                    "DELETE FROM sessions WHERE session_token = ?",
                    [$_SESSION['session_token']]
                );
                
                Security::logSecurityEvent('session_destroyed', [
                    'session_token' => substr($_SESSION['session_token'], 0, 8) . '...',
                    'user_id' => $_SESSION['user_id'] ?? 'unknown'
                ], 'INFO');
            }
            
            // Limpiar variables de sesión
            $_SESSION = [];
            
            // Eliminar cookie de sesión
            if (ini_get('session.use_cookies')) {
                $params = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000,
                    $params['path'], $params['domain'],
                    $params['secure'], $params['httponly']
                );
            }
            
            // Destruir sesión
            session_destroy();
            
            return true;
        } catch (Exception $e) {
            error_log("Error destruyendo sesión: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Limpiar todas las sesiones de un usuario
     */
    public function cleanUserSessions($userId) {
        try {
            $this->db->executeQuery(
                "DELETE FROM sessions WHERE user_id = ?",
                [$userId]
            );
            
            Security::logSecurityEvent('user_sessions_cleaned', [
                'user_id' => $userId
            ], 'INFO');
            
            return true;
        } catch (Exception $e) {
            error_log("Error limpiando sesiones del usuario: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Obtener información de sesiones activas
     */
    public function getActiveSessions($userId = null) {
        try {
            $sql = "
                SELECT s.*, u.username, u.name 
                FROM sessions s 
                JOIN users u ON s.user_id = u.id 
                WHERE s.expires_at > NOW()
            ";
            $params = [];
            
            if ($userId) {
                $sql .= " AND s.user_id = ?";
                $params[] = $userId;
            }
            
            $sql .= " ORDER BY s.created_at DESC";
            
            return $this->db->fetchAll($sql, $params);
        } catch (Exception $e) {
            error_log("Error obteniendo sesiones activas: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Regenerar ID de sesión
     */
    public function regenerateSessionId() {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }
    }
    
    /**
     * Obtener datos de usuario de la sesión
     */
    public function getUserData($key = null) {
        if (!isset($_SESSION['logged_in']) || !$_SESSION['logged_in']) {
            return null;
        }
        
        if ($key === null) {
            // Devolver todos los datos del usuario
            $userData = [];
            foreach ($_SESSION as $sessionKey => $value) {
                if (strpos($sessionKey, 'user_') === 0) {
                    $userKey = substr($sessionKey, 5);
                    $userData[$userKey] = $value;
                }
            }
            return $userData;
        }
        
        return $_SESSION['user_' . $key] ?? null;
    }
    
    /**
     * Establecer datos de usuario en la sesión
     */
    public function setUserData($key, $value) {
        if (isset($_SESSION['logged_in']) && $_SESSION['logged_in']) {
            $_SESSION['user_' . $key] = $value;
            return true;
        }
        return false;
    }
    
    /**
     * Verificar si el usuario está logueado
     */
    public function isLoggedIn() {
        return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] && $this->validateSession();
    }
    
    /**
     * Obtener estadísticas de sesiones
     */
    public function getSessionStats() {
        try {
            $stats = $this->db->fetch("
                SELECT 
                    COUNT(*) as total_active,
                    COUNT(DISTINCT user_id) as unique_users,
                    AVG(TIMESTAMPDIFF(MINUTE, created_at, NOW())) as avg_duration_minutes
                FROM sessions 
                WHERE expires_at > NOW()
            ");
            
            $recentLogins = $this->db->fetch("
                SELECT COUNT(*) as recent_logins
                FROM access_log 
                WHERE action = 'login_success' 
                AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
            ");
            
            return [
                'active_sessions' => (int)$stats['total_active'],
                'unique_users' => (int)$stats['unique_users'],
                'avg_duration_minutes' => round($stats['avg_duration_minutes'], 2),
                'recent_logins_24h' => (int)$recentLogins['recent_logins']
            ];
        } catch (Exception $e) {
            error_log("Error obteniendo estadísticas de sesiones: " . $e->getMessage());
            return [];
        }
    }
    
    // ================================================
    // MANEJADORES PERSONALIZADOS DE SESIÓN
    // ================================================
    
    public function sessionOpen($savePath, $sessionName) {
        return true;
    }
    
    public function sessionClose() {
        return true;
    }
    
    public function sessionRead($sessionId) {
        try {
            $session = $this->db->fetch(
                "SELECT session_data FROM php_sessions WHERE session_id = ? AND expires_at > NOW()",
                [$sessionId]
            );
            
            return $session ? $session['session_data'] : '';
        } catch (Exception $e) {
            error_log("Error leyendo sesión: " . $e->getMessage());
            return '';
        }
    }
    
    public function sessionWrite($sessionId, $sessionData) {
        try {
            $expiresAt = date('Y-m-d H:i:s', time() + SESSION_LIFETIME);
            
            $this->db->executeQuery("
                INSERT INTO php_sessions (session_id, session_data, expires_at) 
                VALUES (?, ?, ?)
                ON DUPLICATE KEY UPDATE 
                session_data = VALUES(session_data),
                expires_at = VALUES(expires_at)
            ", [$sessionId, $sessionData, $expiresAt]);
            
            return true;
        } catch (Exception $e) {
            error_log("Error escribiendo sesión: " . $e->getMessage());
            return false;
        }
    }
    
    public function sessionDestroy($sessionId) {
        try {
            $this->db->executeQuery(
                "DELETE FROM php_sessions WHERE session_id = ?",
                [$sessionId]
            );
            
            return true;
        } catch (Exception $e) {
            error_log("Error destruyendo sesión: " . $e->getMessage());
            return false;
        }
    }
    
    public function sessionGC($maxLifetime) {
        try {
            // Limpiar sesiones PHP expiradas
            $this->db->executeQuery("DELETE FROM php_sessions WHERE expires_at < NOW()");
            
            // Limpiar sesiones de usuario expiradas
            $deleted = $this->db->executeQuery("DELETE FROM sessions WHERE expires_at < NOW()");
            
            // Log de limpieza si se eliminaron sesiones
            if ($deleted > 0) {
                Security::logSecurityEvent('session_gc_cleanup', [
                    'deleted_sessions' => $deleted
                ], 'INFO');
            }
            
            return true;
        } catch (Exception $e) {
            error_log("Error en garbage collection de sesiones: " . $e->getMessage());
            return false;
        }
    }
}

// ================================================
// FUNCIONES HELPER GLOBALES
// ================================================

/**
 * Obtener instancia del manejador de sesiones
 */
function getSessionManager() {
    return SessionManager::getInstance();
}

/**
 * Verificar si el usuario está logueado
 */
function isLoggedIn() {
    return getSessionManager()->isLoggedIn();
}

/**
 * Obtener datos de usuario de la sesión
 */
function getUserData($key = null) {
    return getSessionManager()->getUserData($key);
}

/**
 * Establecer datos de usuario en la sesión
 */
function setUserData($key, $value) {
    return getSessionManager()->setUserData($key, $value);
}

/**
 * Destruir sesión actual
 */
function logout() {
    return getSessionManager()->destroySession();
}

/**
 * Regenerar ID de sesión
 */
function regenerateSession() {
    getSessionManager()->regenerateSessionId();
}

// Crear tabla para sesiones PHP si no existe
try {
    $db = Database::getInstance();
    $db->executeQuery("
        CREATE TABLE IF NOT EXISTS php_sessions (
            session_id VARCHAR(128) PRIMARY KEY,
            session_data LONGTEXT,
            expires_at DATETIME NOT NULL,
            INDEX idx_expires (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");
} catch (Exception $e) {
    error_log("Error creando tabla php_sessions: " . $e->getMessage());
}

// Inicializar automáticamente
getSessionManager();
?>
