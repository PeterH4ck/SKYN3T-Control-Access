<?php
/**
 * Archivo: /var/www/html/api/system/stats.php
 * API endpoint para estadísticas completas del sistema
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
    
    // Verificar permisos para ver estadísticas
    if (!$auth->hasPermission($user, 'view_stats') && 
        !$auth->hasPermission($user, 'dashboard') && 
        !$auth->hasPermission($user, 'all')) {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'message' => 'Sin permisos para ver estadísticas del sistema',
            'error_code' => 'INSUFFICIENT_PERMISSIONS'
        ]);
        exit;
    }
    
    $db = Database::getInstance();
    
    // ================================================
    // ESTADÍSTICAS DE USUARIOS
    // ================================================
    $userStats = $db->fetch("
        SELECT 
            COUNT(*) as total_users,
            SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) as active_users,
            SUM(CASE WHEN role = 'SuperUser' THEN 1 ELSE 0 END) as super_users,
            SUM(CASE WHEN role = 'Admin' THEN 1 ELSE 0 END) as admins,
            SUM(CASE WHEN role = 'SupportAdmin' THEN 1 ELSE 0 END) as support_admins,
            SUM(CASE WHEN role = 'User' THEN 1 ELSE 0 END) as regular_users,
            SUM(CASE WHEN locked_until > NOW() THEN 1 ELSE 0 END) as locked_users,
            SUM(CASE WHEN last_login >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 ELSE 0 END) as active_24h,
            SUM(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 ELSE 0 END) as new_users_30d
        FROM users
    ");
    
    // ================================================
    // ESTADÍSTICAS DE SESIONES
    // ================================================
    $sessionStats = $db->fetch("
        SELECT 
            COUNT(*) as active_sessions,
            COUNT(DISTINCT user_id) as unique_active_users,
            AVG(TIMESTAMPDIFF(MINUTE, created_at, NOW())) as avg_session_duration,
            COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 1 END) as sessions_last_hour
        FROM sessions 
        WHERE expires_at > NOW()
    ");
    
    // ================================================
    // ESTADÍSTICAS DE DISPOSITIVOS
    // ================================================
    $deviceStats = $db->fetch("
        SELECT 
            COUNT(*) as total_devices,
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_devices,
            SUM(CASE WHEN status = 'inactive' THEN 1 ELSE 0 END) as inactive_devices,
            SUM(CASE WHEN status = 'maintenance' THEN 1 ELSE 0 END) as maintenance_devices,
            COUNT(DISTINCT device_type) as device_types,
            SUM(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 ELSE 0 END) as new_devices_30d
        FROM devices
    ");
    
    // ================================================
    // ESTADÍSTICAS DEL RELÉ
    // ================================================
    $relayStats = $db->fetch("
        SELECT 
            COUNT(*) as total_changes,
            SUM(CASE WHEN relay_state = 1 THEN 1 ELSE 0 END) as times_turned_on,
            SUM(CASE WHEN relay_state = 0 THEN 1 ELSE 0 END) as times_turned_off,
            SUM(CASE WHEN change_method = 'web' THEN 1 ELSE 0 END) as web_changes,
            SUM(CASE WHEN change_method = 'physical' THEN 1 ELSE 0 END) as physical_changes,
            SUM(CASE WHEN change_method = 'screen' THEN 1 ELSE 0 END) as screen_changes,
            AVG(CASE WHEN relay_state = 1 THEN 1 ELSE 0 END) * 100 as on_percentage_all_time
        FROM relay_status
    ");
    
    $relayStats24h = $db->fetch("
        SELECT 
            COUNT(*) as changes_24h,
            SUM(CASE WHEN relay_state = 1 THEN 1 ELSE 0 END) as on_times_24h,
            AVG(CASE WHEN relay_state = 1 THEN 1 ELSE 0 END) * 100 as on_percentage_24h
        FROM relay_status 
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ");
    
    // Estado actual del relé
    $currentRelayState = $db->fetch("
        SELECT relay_state, led_state, timestamp, change_method
        FROM relay_status 
        ORDER BY timestamp DESC 
        LIMIT 1
    ");
    
    // ================================================
    // ESTADÍSTICAS DE ACTIVIDAD
    // ================================================
    $activityStats = $db->fetch("
        SELECT 
            COUNT(*) as total_actions,
            COUNT(DISTINCT user_id) as active_users_all_time,
            SUM(CASE WHEN action = 'login_success' THEN 1 ELSE 0 END) as successful_logins,
            SUM(CASE WHEN action = 'login_failed' THEN 1 ELSE 0 END) as failed_logins,
            SUM(CASE WHEN timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 ELSE 0 END) as actions_24h,
            SUM(CASE WHEN timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 ELSE 0 END) as actions_7d
        FROM access_log
    ");
    
    // ================================================
    // ESTADÍSTICAS DE SEGURIDAD
    // ================================================
    $securityStats = $db->fetch("
        SELECT 
            SUM(CASE WHEN action LIKE '%failed%' THEN 1 ELSE 0 END) as total_failed_attempts,
            SUM(CASE WHEN action LIKE '%failed%' AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 ELSE 0 END) as failed_attempts_24h,
            COUNT(DISTINCT ip_address) as unique_ips,
            COUNT(DISTINCT CASE WHEN action = 'login_success' THEN ip_address END) as successful_ips
        FROM access_log
    ");
    
    // ================================================
    // INFORMACIÓN DEL SISTEMA
    // ================================================
    $systemInfo = [
        'version' => getConfig('SYSTEM_VERSION', '2.0.0'),
        'environment' => getConfig('ENVIRONMENT', 'development'),
        'debug_mode' => getConfig('DEBUG_MODE', false),
        'uptime' => getSystemUptime(),
        'server_time' => date('Y-m-d H:i:s'),
        'timezone' => date_default_timezone_get(),
        'php_version' => PHP_VERSION,
        'memory_usage' => formatBytes(memory_get_usage(true)),
        'peak_memory' => formatBytes(memory_get_peak_usage(true))
    ];
    
    // ================================================
    // INFORMACIÓN DE LA BASE DE DATOS
    // ================================================
    $dbInfo = $db->getDatabaseInfo();
    
    // ================================================
    // ACTIVIDAD POR HORAS (ÚLTIMAS 24H)
    // ================================================
    $hourlyActivity = $db->fetchAll("
        SELECT 
            HOUR(timestamp) as hour,
            COUNT(*) as activity_count,
            COUNT(CASE WHEN action = 'login_success' THEN 1 END) as logins,
            COUNT(CASE WHEN action LIKE '%relay%' THEN 1 END) as relay_actions
        FROM access_log 
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY HOUR(timestamp)
        ORDER BY hour
    ");
    
    // ================================================
    // TOP USUARIOS MÁS ACTIVOS
    // ================================================
    $topUsers = $db->fetchAll("
        SELECT 
            u.username, u.name, u.role,
            COUNT(al.id) as total_actions,
            MAX(al.timestamp) as last_activity
        FROM users u
        JOIN access_log al ON u.id = al.user_id
        WHERE al.timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        GROUP BY u.id
        ORDER BY total_actions DESC
        LIMIT 10
    ");
    
    // ================================================
    // GRÁFICOS DE ACTIVIDAD SEMANAL
    // ================================================
    $weeklyActivity = $db->fetchAll("
        SELECT 
            DATE(timestamp) as date,
            COUNT(*) as total_actions,
            COUNT(CASE WHEN action = 'login_success' THEN 1 END) as logins,
            COUNT(DISTINCT user_id) as unique_users
        FROM access_log 
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY DATE(timestamp)
        ORDER BY date
    ");
    
    // ================================================
    // TIPOS DE DISPOSITIVOS
    // ================================================
    $deviceTypes = $db->fetchAll("
        SELECT device_type, COUNT(*) as count, status
        FROM devices 
        GROUP BY device_type, status
        ORDER BY count DESC
    ");
    
    // Log de acceso a estadísticas
    Security::logSecurityEvent('system_stats_accessed', [
        'user_id' => $user['id'],
        'username' => $user['username'],
        'role' => $user['role']
    ], 'INFO');
    
    // ================================================
    // RESPUESTA FINAL
    // ================================================
    echo json_encode([
        'success' => true,
        'system_info' => $systemInfo,
        'database_info' => $dbInfo,
        'statistics' => [
            'users' => [
                'total' => (int)$userStats['total_users'],
                'active' => (int)$userStats['active_users'],
                'super_users' => (int)$userStats['super_users'],
                'admins' => (int)$userStats['admins'],
                'support_admins' => (int)$userStats['support_admins'],
                'regular_users' => (int)$userStats['regular_users'],
                'locked' => (int)$userStats['locked_users'],
                'active_24h' => (int)$userStats['active_24h'],
                'new_30d' => (int)$userStats['new_users_30d']
            ],
            'sessions' => [
                'active' => (int)$sessionStats['active_sessions'],
                'unique_users' => (int)$sessionStats['unique_active_users'],
                'avg_duration_minutes' => round($sessionStats['avg_session_duration'], 2),
                'last_hour' => (int)$sessionStats['sessions_last_hour']
            ],
            'devices' => [
                'total' => (int)$deviceStats['total_devices'],
                'active' => (int)$deviceStats['active_devices'],
                'inactive' => (int)$deviceStats['inactive_devices'],
                'maintenance' => (int)$deviceStats['maintenance_devices'],
                'types_count' => (int)$deviceStats['device_types'],
                'new_30d' => (int)$deviceStats['new_devices_30d']
            ],
            'relay' => [
                'current_state' => $currentRelayState ? [
                    'relay_on' => (bool)$currentRelayState['relay_state'],
                    'led_on' => (bool)$currentRelayState['led_state'],
                    'last_change' => $currentRelayState['timestamp'],
                    'method' => $currentRelayState['change_method']
                ] : null,
                'total_changes' => (int)$relayStats['total_changes'],
                'times_on' => (int)$relayStats['times_turned_on'],
                'times_off' => (int)$relayStats['times_turned_off'],
                'web_changes' => (int)$relayStats['web_changes'],
                'physical_changes' => (int)$relayStats['physical_changes'],
                'screen_changes' => (int)$relayStats['screen_changes'],
                'on_percentage_all_time' => round($relayStats['on_percentage_all_time'], 2),
                'changes_24h' => (int)$relayStats24h['changes_24h'],
                'on_percentage_24h' => round($relayStats24h['on_percentage_24h'], 2)
            ],
            'activity' => [
                'total_actions' => (int)$activityStats['total_actions'],
                'active_users_all_time' => (int)$activityStats['active_users_all_time'],
                'successful_logins' => (int)$activityStats['successful_logins'],
                'failed_logins' => (int)$activityStats['failed_logins'],
                'actions_24h' => (int)$activityStats['actions_24h'],
                'actions_7d' => (int)$activityStats['actions_7d']
            ],
            'security' => [
                'total_failed_attempts' => (int)$securityStats['total_failed_attempts'],
                'failed_attempts_24h' => (int)$securityStats['failed_attempts_24h'],
                'unique_ips' => (int)$securityStats['unique_ips'],
                'successful_ips' => (int)$securityStats['successful_ips'],
                'success_rate' => $activityStats['successful_logins'] > 0 ? 
                    round(($activityStats['successful_logins'] / ($activityStats['successful_logins'] + $activityStats['failed_logins'])) * 100, 2) : 0
            ]
        ],
        'charts_data' => [
            'hourly_activity' => array_map(function($item) {
                return [
                    'hour' => (int)$item['hour'],
                    'activity' => (int)$item['activity_count'],
                    'logins' => (int)$item['logins'],
                    'relay_actions' => (int)$item['relay_actions']
                ];
            }, $hourlyActivity),
            'weekly_activity' => array_map(function($item) {
                return [
                    'date' => $item['date'],
                    'total_actions' => (int)$item['total_actions'],
                    'logins' => (int)$item['logins'],
                    'unique_users' => (int)$item['unique_users']
                ];
            }, $weeklyActivity),
            'device_types' => array_map(function($item) {
                return [
                    'type' => $item['device_type'],
                    'count' => (int)$item['count'],
                    'status' => $item['status']
                ];
            }, $deviceTypes)
        ],
        'top_users' => array_map(function($item) {
            return [
                'username' => $item['username'],
                'name' => $item['name'],
                'role' => $item['role'],
                'actions' => (int)$item['total_actions'],
                'last_activity' => $item['last_activity']
            ];
        }, $topUsers),
        'generated_by' => [
            'user_id' => $user['id'],
            'username' => $user['username'],
            'role' => $user['role']
        ],
        'timestamp' => date('Y-m-d H:i:s')
    ]);
    
} catch (Exception $e) {
    error_log("Error obteniendo estadísticas del sistema: " . $e->getMessage());
    
    // Log del error
    Security::logSecurityEvent('system_stats_error', [
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
 * Obtener uptime del sistema (aproximado)
 */
function getSystemUptime() {
    try {
        if (function_exists('sys_getloadavg') && file_exists('/proc/uptime')) {
            $uptime = file_get_contents('/proc/uptime');
            $uptime = explode(' ', $uptime);
            $seconds = (int)$uptime[0];
            
            $days = floor($seconds / 86400);
            $hours = floor(($seconds % 86400) / 3600);
            $minutes = floor(($seconds % 3600) / 60);
            
            return [
                'seconds' => $seconds,
                'formatted' => "{$days}d {$hours}h {$minutes}m"
            ];
        }
        
        return [
            'seconds' => null,
            'formatted' => 'No disponible'
        ];
    } catch (Exception $e) {
        return [
            'seconds' => null,
            'formatted' => 'Error'
        ];
    }
}

/**
 * Formatear bytes en formato legible
 */
function formatBytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    
    for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
        $bytes /= 1024;
    }
    
    return round($bytes, $precision) . ' ' . $units[$i];
}
?>
