<?php
/**
 * Archivo: /var/www/html/api/users/profile.php
 * API endpoint para obtener perfil del usuario actual
 */

// Definir constante del sistema
define('SKYN3T_SYSTEM', true);

// Headers de seguridad y CORS
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Manejo de solicitudes OPTIONS (CORS preflight)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Solo permitir GET
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'message' => 'Método no permitido',
        'error_code' => 'METHOD_NOT_ALLOWED'
    ]);
    exit;
}

// Incluir sistema de autenticación
require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/database.php';
require_once __DIR__ . '/../../includes/security.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/session.php';

try {
    // Verificar autenticación
    $auth = Auth::getInstance();
    $user = $auth->requireAuth();
    
    if (!$user) {
        exit; // requireAuth ya maneja la respuesta
    }
    
    $db = Database::getInstance();
    
    // Obtener información completa del usuario desde la base de datos
    $userProfile = $db->fetch("
        SELECT 
            id, username, name, email, role, privileges, active, is_active,
            last_login, created_at, updated_at, failed_attempts,
            CASE 
                WHEN locked_until > NOW() THEN locked_until 
                ELSE NULL 
            END as locked_until
        FROM users 
        WHERE id = ?
    ", [$user['id']]);
    
    if (!$userProfile) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'message' => 'Usuario no encontrado',
            'error_code' => 'USER_NOT_FOUND'
        ]);
        exit;
    }
    
    // Obtener sesiones activas del usuario
    $activeSessions = $db->fetchAll("
        SELECT session_token, created_at, expires_at, ip_address, user_agent
        FROM sessions 
        WHERE user_id = ? AND expires_at > NOW()
        ORDER BY created_at DESC
    ", [$user['id']]);
    
    // Obtener actividad reciente del usuario
    $recentActivity = $db->fetchAll("
        SELECT action, timestamp, ip_address
        FROM access_log 
        WHERE user_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 10
    ", [$user['id']]);
    
    // Obtener estadísticas de actividad
    $activityStats = $db->fetch("
        SELECT 
            COUNT(*) as total_logins,
            MAX(timestamp) as last_activity,
            COUNT(DISTINCT DATE(timestamp)) as active_days
        FROM access_log 
        WHERE user_id = ? AND action = 'login_success'
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    ", [$user['id']]);
    
    // Obtener dispositivos creados por el usuario
    $devicesCreated = $db->fetch("
        SELECT COUNT(*) as count 
        FROM devices 
        WHERE created_by = ?
    ", [$user['id']]);
    
    // Decodificar privilegios
    $privileges = [];
    if (!empty($userProfile['privileges'])) {
        $privileges = json_decode($userProfile['privileges'], true) ?: [];
    }
    
    // Formatear sesiones activas (ocultando información sensible)
    $formattedSessions = array_map(function($session) {
        return [
            'token_preview' => substr($session['session_token'], 0, 8) . '...',
            'created_at' => $session['created_at'],
            'expires_at' => $session['expires_at'],
            'ip_address' => $session['ip_address'],
            'user_agent' => $session['user_agent'],
            'is_current' => isset($_SESSION['session_token']) && 
                           $_SESSION['session_token'] === $session['session_token']
        ];
    }, $activeSessions);
    
    // Formatear actividad reciente
    $formattedActivity = array_map(function($activity) {
        return [
            'action' => $activity['action'],
            'timestamp' => $activity['timestamp'],
            'ip_address' => $activity['ip_address'],
            'time_ago' => timeAgo($activity['timestamp'])
        ];
    }, $recentActivity);
    
    // Calcular tiempo desde último login
    $lastLoginAgo = null;
    if ($userProfile['last_login']) {
        $lastLoginAgo = timeAgo($userProfile['last_login']);
    }
    
    // Determinar estado del usuario
    $userStatus = 'active';
    if (!$userProfile['active'] || !$userProfile['is_active']) {
        $userStatus = 'inactive';
    } elseif ($userProfile['locked_until']) {
        $userStatus = 'locked';
    } elseif (count($activeSessions) > 0) {
        $userStatus = 'online';
    }
    
    // Log de acceso al perfil
    Security::logSecurityEvent('profile_accessed', [
        'user_id' => $user['id'],
        'username' => $user['username']
    ], 'INFO');
    
    // Respuesta exitosa
    echo json_encode([
        'success' => true,
        'profile' => [
            'id' => (int)$userProfile['id'],
            'username' => $userProfile['username'],
            'name' => $userProfile['name'],
            'email' => $userProfile['email'],
            'role' => $userProfile['role'],
            'privileges' => $privileges,
            'status' => $userStatus,
            'active' => (bool)$userProfile['active'],
            'is_active' => (bool)$userProfile['is_active'],
            'is_locked' => !is_null($userProfile['locked_until']),
            'locked_until' => $userProfile['locked_until'],
            'failed_attempts' => (int)$userProfile['failed_attempts'],
            'last_login' => $userProfile['last_login'],
            'last_login_ago' => $lastLoginAgo,
            'created_at' => $userProfile['created_at'],
            'updated_at' => $userProfile['updated_at'],
            'account_age_days' => floor((time() - strtotime($userProfile['created_at'])) / 86400)
        ],
        'sessions' => [
            'active_count' => count($activeSessions),
            'sessions' => $formattedSessions
        ],
        'activity' => [
            'recent' => $formattedActivity,
            'stats_30_days' => [
                'total_logins' => (int)$activityStats['total_logins'],
                'last_activity' => $activityStats['last_activity'],
                'active_days' => (int)$activityStats['active_days']
            ]
        ],
        'contributions' => [
            'devices_created' => (int)$devicesCreated['count']
        ],
        'permissions' => [
            'can_manage_users' => $auth->hasPermission($user, 'manage_users'),
            'can_manage_devices' => $auth->hasPermission($user, 'manage_devices'),
            'can_control_relay' => $auth->hasPermission($user, 'control_relay'),
            'can_view_logs' => $auth->hasPermission($user, 'view_logs'),
            'can_view_dashboard' => $auth->hasPermission($user, 'dashboard'),
            'is_admin' => in_array($user['role'], ['Admin', 'SuperUser']),
            'is_super_user' => $user['role'] === 'SuperUser'
        ],
        'security' => [
            'password_last_changed' => null, // Placeholder para futura implementación
            'two_factor_enabled' => false,   // Placeholder para futura implementación
            'login_notifications' => true    // Placeholder para futura implementación
        ],
        'timestamp' => date('Y-m-d H:i:s')
    ]);
    
} catch (Exception $e) {
    error_log("Error obteniendo perfil: " . $e->getMessage());
    
    // Log del error
    Security::logSecurityEvent('profile_error', [
        'error' => $e->getMessage(),
        'user_id' => $user['id'] ?? null
    ], 'ERROR');
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Error interno del servidor',
        'error_code' => 'INTERNAL_ERROR'
    ]);
}

/**
 * Calcular tiempo transcurrido desde una fecha
 */
function timeAgo($datetime) {
    $time = time() - strtotime($datetime);
    
    if ($time < 60) {
        return 'hace ' . $time . ' segundo' . ($time != 1 ? 's' : '');
    } elseif ($time < 3600) {
        $minutes = floor($time / 60);
        return 'hace ' . $minutes . ' minuto' . ($minutes != 1 ? 's' : '');
    } elseif ($time < 86400) {
        $hours = floor($time / 3600);
        return 'hace ' . $hours . ' hora' . ($hours != 1 ? 's' : '');
    } elseif ($time < 2592000) {
        $days = floor($time / 86400);
        return 'hace ' . $days . ' día' . ($days != 1 ? 's' : '');
    } else {
        $months = floor($time / 2592000);
        return 'hace ' . $months . ' mes' . ($months != 1 ? 'es' : '');
    }
}
?>
