<?php
/**
 * SKYN3T - Sistema de Control y Monitoreo
 * Manejo avanzado de sesiones
 * 
 * @version 2.0.0
 * @date 2025-01-19
 */

// Incluir configuración
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';

/**
 * Clase para manejo de sesiones en base de datos
 */
class SessionManager {
    private static $instance = null;
    private $db = null;
    private $session_started = false;
    
    /**
     * Constructor privado (Singleton)
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
     * Inicializar sesión PHP
     */
    private function initializeSession() {
        if (php_sapi_name() !== 'cli' && session_status() === PHP_SESSION_NONE) {
            // Configuración de sesión segura
            ini_set('session.use_strict_mode', 1);
            ini_set('session.use_cookies', 1);
            ini_set('session.use_only_cookies', 1);
            ini_set('session.cookie_httponly', 1);
            ini_set('session.cookie_secure', ENVIRONMENT === 'production' ? 1 : 0);
            ini_set('session.cookie_samesite', 'Lax');
            ini_set('session.gc_maxlifetime', SESSION_LIFETIME * 60);
            
            // Nombre de sesión personalizado
            session_name('SKYN3T_SESSION');
            
            // Iniciar sesión
            session_start();
            $this->session_started = true;
            
            // Regenerar ID de sesión periódicamente
            if (!isset($_SESSION['last_regeneration'])) {
                $_SESSION['last_regeneration'] = time();
            } elseif (time() - $_SESSION['last_regeneration'] > SESSION_REGENERATE_TIME) {
                $this->regenerateSessionId();
            }
        }
    }
    
    /**
     * Crear nueva sesión
     */
    public function createSession($user_id, $user_data = []) {
        try {
            // Generar token único
            $session_token = generate_secure_token(32);
            $session_id = session_id();
            
            // Preparar datos de sesión
            $ip_address = get_client_ip();
            $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
            
            // Verificar sesiones activas del usuario
            $active_sessions = $this->getActiveUserSessions($user_id);
            
            // Limitar número de sesiones concurrentes
            $max_sessions = 5; // Configurable
            if (count($active_sessions) >= $max_sessions) {
                // Cerrar la sesión más antigua
                $oldest = $active_sessions[0];
                $this->destroySession($oldest['session_token']);
            }
            
            // Insertar nueva sesión en DB
            $stmt = $this->db->execute(
                "INSERT INTO " . TABLE_SESSIONS . " 
                (user_id, session_id, session_token, ip_address, user_agent, created_at, last_activity, is_active) 
                VALUES (?, ?, ?, ?, ?, NOW(), NOW(), 1)",
                [$user_id, $session_id, $session_token, $ip_address, $user_agent]
            );
            
            // Guardar en sesión PHP
            $_SESSION['user_id'] = $user_id;
            $_SESSION['session_token'] = $session_token;
            $_SESSION['user_data'] = $user_data;
            $_SESSION['login_time'] = time();
            $_SESSION['last_activity'] = time();
            
            // Log de actividad
            log_activity('session_created', $user_id, [
                'ip' => $ip_address,
                'user_agent' => substr($user_agent, 0, 100)
            ]);
            
            return [
                'success' => true,
                'token' => $session_token,
                'session_id' => $session_id
            ];
            
        } catch (Exception $e) {
            error_log("Create session error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Validar sesión
     */
    public function validateSession($token) {
        try {
            // Buscar sesión en DB
            $stmt = $this->db->execute(
                "SELECT s.*, u.username, u.role, u.active as user_active
                FROM " . TABLE_SESSIONS . " s
                JOIN " . TABLE_USERS . " u ON u.id = s.user_id
                WHERE s.session_token = ? AND s.is_active = 1",
                [$token]
            );
            
            $session = $stmt->fetch();
            
            if (!$session) {
                return ['valid' => false, 'reason' => 'Session not found'];
            }
            
            // Verificar que el usuario esté activo
            if (!$session['user_active']) {
                $this->destroySession($token);
                return ['valid' => false, 'reason' => 'User inactive'];
            }
            
            // Verificar timeout
            $last_activity = strtotime($session['last_activity']);
            $timeout = SESSION_LIFETIME * 60;
            
            if ((time() - $last_activity) > $timeout) {
                $this->destroySession($token);
                return ['valid' => false, 'reason' => 'Session timeout'];
            }
            
            // Verificar cambio de IP (opcional)
            $current_ip = get_client_ip();
            if ($session['ip_address'] !== $current_ip) {
                // Log de seguridad
                security_log('session_ip_change', $session['user_id'], [
                    'original_ip' => $session['ip_address'],
                    'current_ip' => $current_ip
                ]);
                
                // Opcional: invalidar sesión por cambio de IP
                // $this->destroySession($token);
                // return ['valid' => false, 'reason' => 'IP address changed'];
            }
            
            // Actualizar última actividad
            $this->updateLastActivity($token);
            
            return [
                'valid' => true,
                'user' => [
                    'id' => $session['user_id'],
                    'username' => $session['username'],
                    'role' => $session['role']
                ]
            ];
            
        } catch (Exception $e) {
            error_log("Validate session error: " . $e->getMessage());
            return ['valid' => false, 'reason' => 'Validation error'];
        }
    }
    
    /**
     * Destruir sesión
     */
    public function destroySession($token) {
        try {
            // Obtener información de la sesión
            $session = $this->getSessionByToken($token);
            
            if ($session) {
                // Marcar como inactiva en DB
                $stmt = $this->db->execute(
                    "UPDATE " . TABLE_SESSIONS . " 
                    SET is_active = 0, destroyed_at = NOW() 
                    WHERE session_token = ?",
                    [$token]
                );
                
                // Log de actividad
                log_activity('session_destroyed', $session['user_id'], [
                    'session_duration' => time() - strtotime($session['created_at'])
                ]);
            }
            
            // Destruir sesión PHP si es la actual
            if (isset($_SESSION['session_token']) && $_SESSION['session_token'] === $token) {
                $_SESSION = [];
                if (ini_get("session.use_cookies")) {
                    $params = session_get_cookie_params();
                    setcookie(session_name(), '', time() - 42000,
                        $params["path"], $params["domain"],
                        $params["secure"], $params["httponly"]
                    );
                }
                session_destroy();
            }
            
            return true;
            
        } catch (Exception $e) {
            error_log("Destroy session error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Actualizar última actividad
     */
    private function updateLastActivity($token) {
        try {
            $stmt = $this->db->execute(
                "UPDATE " . TABLE_SESSIONS . " 
                SET last_activity = NOW() 
                WHERE session_token = ?",
                [$token]
            );
            
            // Actualizar también en sesión PHP
            if (isset($_SESSION['session_token']) && $_SESSION['session_token'] === $token) {
                $_SESSION['last_activity'] = time();
            }
            
            return true;
            
        } catch (Exception $e) {
            error_log("Update activity error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Obtener sesión por token
     */
    public function getSessionByToken($token) {
        try {
            $stmt = $this->db->execute(
                "SELECT * FROM " . TABLE_SESSIONS . " WHERE session_token = ?",
                [$token]
            );
            
            return $stmt->fetch();
            
        } catch (Exception $e) {
            error_log("Get session error: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Obtener sesiones activas de un usuario
     */
    public function getActiveUserSessions($user_id) {
        try {
            $stmt = $this->db->execute(
                "SELECT * FROM " . TABLE_SESSIONS . " 
                WHERE user_id = ? AND is_active = 1 
                ORDER BY created_at ASC",
                [$user_id]
            );
            
            return $stmt->fetchAll();
            
        } catch (Exception $e) {
            error_log("Get user sessions error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Invalidar todas las sesiones de un usuario
     */
    public function invalidateUserSessions($user_id, $except_current = false) {
        try {
            $sql = "UPDATE " . TABLE_SESSIONS . " 
                    SET is_active = 0, destroyed_at = NOW() 
                    WHERE user_id = ? AND is_active = 1";
            
            $params = [$user_id];
            
            if ($except_current && isset($_SESSION['session_token'])) {
                $sql .= " AND session_token != ?";
                $params[] = $_SESSION['session_token'];
            }
            
            $stmt = $this->db->execute($sql, $params);
            
            // Log de actividad
            log_activity('sessions_invalidated', $user_id, [
                'sessions_affected' => $stmt->rowCount(),
                'except_current' => $except_current
            ]);
            
            return true;
            
        } catch (Exception $e) {
            error_log("Invalidate sessions error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Regenerar ID de sesión
     */
    private function regenerateSessionId() {
        if ($this->session_started) {
            $old_session_id = session_id();
            session_regenerate_id(true);
            $new_session_id = session_id();
            
            $_SESSION['last_regeneration'] = time();
            
            // Actualizar en DB si hay token
            if (isset($_SESSION['session_token'])) {
                try {
                    $stmt = $this->db->execute(
                        "UPDATE " . TABLE_SESSIONS . " 
                        SET session_id = ? 
                        WHERE session_token = ?",
                        [$new_session_id, $_SESSION['session_token']]
                    );
                } catch (Exception $e) {
                    error_log("Update session ID error: " . $e->getMessage());
                }
            }
            
            return true;
        }
        
        return false;
    }
    
    /**
     * Limpiar sesiones expiradas
     */
    public function cleanupExpiredSessions() {
        try {
            // Calcular tiempo de expiración
            $expiry_time = date('Y-m-d H:i:s', time() - (SESSION_LIFETIME * 60));
            
            // Marcar como inactivas las sesiones expiradas
            $stmt = $this->db->execute(
                "UPDATE " . TABLE_SESSIONS . " 
                SET is_active = 0, destroyed_at = NOW() 
                WHERE is_active = 1 AND last_activity < ?",
                [$expiry_time]
            );
            
            $expired_count = $stmt->rowCount();
            
            // Eliminar sesiones muy antiguas (30 días)
            $delete_time = date('Y-m-d H:i:s', time() - (30 * 24 * 60 * 60));
            
            $stmt = $this->db->execute(
                "DELETE FROM " . TABLE_SESSIONS . " 
                WHERE destroyed_at IS NOT NULL AND destroyed_at < ?",
                [$delete_time]
            );
            
            $deleted_count = $stmt->rowCount();
            
            if (LOG_DEBUG) {
                debug_log("Session cleanup: $expired_count expired, $deleted_count deleted");
            }
            
            return [
                'expired' => $expired_count,
                'deleted' => $deleted_count
            ];
            
        } catch (Exception $e) {
            error_log("Cleanup sessions error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Obtener estadísticas de sesiones
     */
    public function getSessionStats() {
        try {
            $stats = [];
            
            // Total de sesiones activas
            $stmt = $this->db->execute(
                "SELECT COUNT(*) as count FROM " . TABLE_SESSIONS . " WHERE is_active = 1"
            );
            $stats['active_sessions'] = $stmt->fetch()['count'];
            
            // Usuarios únicos con sesión activa
            $stmt = $this->db->execute(
                "SELECT COUNT(DISTINCT user_id) as count FROM " . TABLE_SESSIONS . " WHERE is_active = 1"
            );
            $stats['unique_users'] = $stmt->fetch()['count'];
            
            // Sesiones creadas hoy
            $stmt = $this->db->execute(
                "SELECT COUNT(*) as count FROM " . TABLE_SESSIONS . " 
                WHERE DATE(IFNULL(created_at, last_activity)) = CURDATE()"
            );
            $stats['sessions_today'] = $stmt->fetch()['count'];
            
            // Duración promedio de sesión (últimas 24h)
            $stmt = $this->db->execute(
                "SELECT AVG(TIMESTAMPDIFF(MINUTE, IFNULL(created_at, last_activity), IFNULL(destroyed_at, NOW()))) as avg_duration
                FROM " . TABLE_SESSIONS . "
                WHERE IFNULL(created_at, last_activity) >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
            );
            $stats['avg_session_duration'] = round($stmt->fetch()['avg_duration'] ?? 0);
            
            return $stats;
            
        } catch (Exception $e) {
            error_log("Session stats error: " . $e->getMessage());
            return [];
        }
    }
}

// ===========================
// FUNCIONES HELPER
// ===========================

/**
 * Obtener gestor de sesiones
 */
function get_session_manager() {
    return SessionManager::getInstance();
}

/**
 * Verificar si hay sesión activa
 */
function has_active_session() {
    if (isset($_SESSION['session_token'])) {
        $manager = get_session_manager();
        $validation = $manager->validateSession($_SESSION['session_token']);
        return $validation['valid'];
    }
    return false;
}

/**
 * Obtener token de sesión actual
 */
function get_current_session_token() {
    return $_SESSION['session_token'] ?? null;
}

/**
 * Guardar dato en sesión
 */
function session_set($key, $value) {
    $_SESSION[$key] = $value;
}

/**
 * Obtener dato de sesión
 */
function session_get($key, $default = null) {
    return $_SESSION[$key] ?? $default;
}

/**
 * Eliminar dato de sesión
 */
function session_remove($key) {
    unset($_SESSION[$key]);
}

/**
 * Crear mensaje flash
 */
function flash_message($message, $type = 'info') {
    if (!isset($_SESSION['flash_messages'])) {
        $_SESSION['flash_messages'] = [];
    }
    
    $_SESSION['flash_messages'][] = [
        'message' => $message,
        'type' => $type,
        'timestamp' => time()
    ];
}

/**
 * Obtener y limpiar mensajes flash
 */
function get_flash_messages() {
    $messages = $_SESSION['flash_messages'] ?? [];
    $_SESSION['flash_messages'] = [];
    return $messages;
}

// Ejecutar limpieza periódica (probabilística)
if (rand(1, 100) === 1) {
    $manager = SessionManager::getInstance();
    $manager->cleanupExpiredSessions();
}
?>
