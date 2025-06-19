<?php
/**
 * SKYN3T - Sistema de Logout
 * Archivo: /var/www/html/login/logout.php
 * Endpoint para cerrar sesión de forma segura
 * 
 * @version 2.0
 * @author SKYN3T Team
 * @database skyn3t_db (MariaDB)
 */

// Inicializar sistema
require_once '/var/www/html/includes/init.php';

// Headers de API y seguridad
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');

// Manejar preflight CORS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Permitir GET y POST para flexibilidad
if (!in_array($_SERVER['REQUEST_METHOD'], ['GET', 'POST'])) {
    sendErrorResponse('Método no permitido. Use GET o POST para cerrar sesión.', 405, 'METHOD_NOT_ALLOWED');
}

try {
    // Obtener información del cliente
    $clientIP = getClientIP();
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    
    // Obtener información del usuario actual antes del logout
    $currentUser = null;
    $sessionToken = null;
    
    // Intentar obtener información de la sesión actual
    try {
        $auth = new Auth();
        $sessionResult = $auth->verifySession();
        
        if ($sessionResult['valid']) {
            $currentUser = $sessionResult['user'];
            $sessionToken = $sessionResult['session']['token'];
        }
    } catch (Exception $e) {
        // Si hay error obteniendo la sesión, continuamos con el logout de todos modos
        writeLog('warning', 'Error obteniendo sesión durante logout: ' . $e->getMessage());
    }
    
    // Determinar tipo de logout
    $logoutType = $_GET['type'] ?? 'normal';
    $logoutAllSessions = isset($_GET['all_sessions']) && $_GET['all_sessions'] === 'true';
    
    // Procesar logout
    $logoutResult = performLogout($currentUser, $sessionToken, $logoutType, $logoutAllSessions);
    
    // Registrar logout
    writeLog('info', 'Logout ejecutado', [
        'user_id' => $currentUser['id'] ?? null,
        'username' => $currentUser['username'] ?? 'unknown',
        'logout_type' => $logoutType,
        'all_sessions' => $logoutAllSessions,
        'success' => $logoutResult['success'],
        'ip' => $clientIP,
        'user_agent' => substr($userAgent, 0, 100)
    ]);
    
    if ($logoutResult['success']) {
        // Logout exitoso
        sendSuccessResponse([
            'message' => $logoutResult['message'],
            'logout_type' => $logoutType,
            'sessions_closed' => $logoutResult['sessions_closed'],
            'user_info' => $currentUser ? [
                'username' => $currentUser['username'],
                'name' => $currentUser['name']
            ] : null,
            'redirect' => '/login/index_login.html',
            'actions' => [
                'login' => '/login/index_login.html',
                'home' => '/index.html'
            ],
            'system' => [
                'name' => SystemConfig::SYSTEM_NAME,
                'logout_time' => date('Y-m-d H:i:s')
            ]
        ], 'Sesión cerrada correctamente');
        
    } else {
        // Error en logout
        sendErrorResponse(
            $logoutResult['message'], 
            500, 
            'LOGOUT_ERROR'
        );
    }
    
} catch (Exception $e) {
    // Error crítico
    writeLog('error', 'Error crítico en logout: ' . $e->getMessage(), [
        'ip' => $clientIP ?? 'unknown',
        'user_agent' => substr($userAgent ?? 'unknown', 0, 100),
        'error_trace' => $e->getTraceAsString()
    ]);
    
    // Aunque haya error, intentar limpiar sesión local
    try {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    } catch (Exception $sessionError) {
        // Ignorar errores de sesión en este punto
    }
    
    sendErrorResponse(
        'Error interno del sistema durante logout', 
        500, 
        'LOGOUT_SYSTEM_ERROR'
    );
}

/**
 * Ejecutar proceso de logout
 */
function performLogout($user, $sessionToken, $logoutType, $logoutAllSessions) {
    try {
        $db = Database::getInstance();
        $sessionsDeleted = 0;
        
        // Iniciar transacción
        $db->beginTransaction();
        
        if ($user && $sessionToken) {
            if ($logoutAllSessions) {
                // Cerrar todas las sesiones del usuario
                $stmt = $db->prepare("DELETE FROM sessions WHERE user_id = ?", [$user['id']]);
                
                if ($stmt) {
                    // Contar sesiones eliminadas
                    $countStmt = $db->fetchOne("SELECT COUNT(*) as count FROM sessions WHERE user_id = ?", [$user['id']]);
                    $sessionsDeleted = $countStmt['count'] ?? 0;
                    
                    // Eliminar todas las sesiones
                    $db->prepare("DELETE FROM sessions WHERE user_id = ?", [$user['id']]);
                    
                    writeLog('info', 'Logout de todas las sesiones', [
                        'user_id' => $user['id'],
                        'username' => $user['username'],
                        'sessions_deleted' => $sessionsDeleted
                    ]);
                } else {
                    throw new Exception('Error eliminando todas las sesiones del usuario');
                }
            } else {
                // Cerrar solo la sesión actual
                $stmt = $db->prepare("DELETE FROM sessions WHERE session_token = ?", [$sessionToken]);
                
                if ($stmt) {
                    $sessionsDeleted = 1;
                } else {
                    throw new Exception('Error eliminando sesión actual');
                }
            }
            
            // Crear notificación de logout si es necesario
            if ($logoutType === 'security' || $logoutAllSessions) {
                createNotification(
                    'security',
                    'Cierre de Sesión de Seguridad',
                    $logoutAllSessions ? 
                        'Se han cerrado todas las sesiones activas por motivos de seguridad' :
                        'Sesión cerrada por motivos de seguridad',
                    $user['id']
                );
            }
        }
        
        // Limpiar sesión PHP
        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION = [];
            
            // Eliminar cookie de sesión
            if (ini_get("session.use_cookies")) {
                $params = session_get_cookie_params();
                setcookie(
                    session_name(),
                    '',
                    time() - 42000,
                    $params["path"],
                    $params["domain"],
                    $params["secure"],
                    $params["httponly"]
                );
            }
            
            session_unset();
            session_destroy();
        }
        
        // Limpiar cookies adicionales de seguridad
        $cookiesToClear = ['remember_token', 'user_preferences', 'last_activity'];
        foreach ($cookiesToClear as $cookie) {
            if (isset($_COOKIE[$cookie])) {
                setcookie($cookie, '', time() - 3600, '/');
            }
        }
        
        // Confirmar transacción
        $db->commit();
        
        return [
            'success' => true,
            'message' => $logoutAllSessions ? 
                'Todas las sesiones han sido cerradas exitosamente' :
                'Sesión cerrada exitosamente',
            'sessions_closed' => $sessionsDeleted
        ];
        
    } catch (Exception $e) {
        // Rollback en caso de error
        if ($db && $db->inTransaction()) {
            $db->rollback();
        }
        
        writeLog('error', 'Error en proceso de logout: ' . $e->getMessage());
        
        return [
            'success' => false,
            'message' => 'Error durante el proceso de logout: ' . $e->getMessage(),
            'sessions_closed' => 0
        ];
    }
}

/**
 * Función para logout forzado (para usar desde otros scripts)
 */
function forceLogout($userId, $reason = 'forced_logout') {
    try {
        $db = Database::getInstance();
        
        // Obtener información del usuario
        $user = $db->fetchOne("SELECT id, username, name FROM usuarios WHERE id = ?", [$userId]);
        
        if ($user) {
            // Eliminar todas las sesiones del usuario
            $db->prepare("DELETE FROM sessions WHERE user_id = ?", [$userId]);
            
            // Registrar logout forzado
            writeLog('warning', 'Logout forzado ejecutado', [
                'user_id' => $userId,
                'username' => $user['username'],
                'reason' => $reason,
                'forced_by' => 'system'
            ]);
            
            // Crear notificación
            createNotification(
                'warning',
                'Sesión Cerrada por el Sistema',
                "Tu sesión ha sido cerrada por motivos de seguridad: $reason",
                $userId
            );
            
            return true;
        }
        
        return false;
        
    } catch (Exception $e) {
        writeLog('error', 'Error en logout forzado: ' . $e->getMessage());
        return false;
    }
}

/**
 * Limpieza automática de sesiones expiradas
 */
function cleanupExpiredSessions() {
    try {
        $db = Database::getInstance();
        
        // Contar sesiones expiradas antes de eliminar
        $expiredCount = $db->fetchOne("SELECT COUNT(*) as count FROM sessions WHERE expires_at <= NOW()");
        
        if ($expiredCount['count'] > 0) {
            // Eliminar sesiones expiradas
            $db->prepare("DELETE FROM sessions WHERE expires_at <= NOW()");
            
            writeLog('info', 'Limpieza de sesiones expiradas', [
                'sessions_deleted' => $expiredCount['count']
            ]);
        }
        
    } catch (Exception $e) {
        writeLog('error', 'Error en limpieza de sesiones expiradas: ' . $e->getMessage());
    }
}

// Ejecutar limpieza de sesiones expiradas ocasionalmente
if (rand(1, 20) === 1) { // 5% de probabilidad
    cleanupExpiredSessions();
}

/**
 * Función para obtener estadísticas de logout (solo en debug)
 */
if (isDebugMode() && isset($_GET['stats'])) {
    try {
        $db = Database::getInstance();
        
        $stats = $db->fetchAll("
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as logout_count
            FROM access_log 
            WHERE action = 'logout' 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        ");
        
        writeLog('debug', 'Estadísticas de logout (últimos 7 días)', $stats);
        
    } catch (Exception $e) {
        writeLog('error', 'Error obteniendo estadísticas de logout: ' . $e->getMessage());
    }
}
?>