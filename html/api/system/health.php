// ===========================
// ARCHIVO: /var/www/html/api/system/health.php
// DESCRIPCIÓN: Estado de salud del sistema
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

// Solo permitir GET
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
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

try {
    $components = [];
    
    // 1. Estado de la base de datos
    $db_health = check_database_health();
    $components['database'] = $db_health;
    
    // 2. Estado del gestor de sesiones
    $session_health = check_session_health();
    $components['session_manager'] = $session_health;
    
    // 3. Estado del controlador de relé
    $relay_health = check_relay_health();
    $components['relay_controller'] = $relay_health;
    
    // 4. Estado del sistema de archivos
    $fs_health = check_filesystem_health();
    $components['file_system'] = $fs_health;
    
    // 5. Estado del servidor web
    $web_health = check_webserver_health();
    $components['web_server'] = $web_health;
    
    // Determinar estado general
    $all_statuses = array_column($components, 'status');
    if (in_array('critical', $all_statuses)) {
        $overall_status = 'critical';
    } elseif (in_array('warning', $all_statuses)) {
        $overall_status = 'warning';
    } else {
        $overall_status = 'healthy';
    }
    
    echo json_encode([
        'success' => true,
        'status' => $overall_status,
        'components' => $components,
        'checked_at' => date('Y-m-d H:i:s')
    ]);
    
} catch (Exception $e) {
    error_log("Health check error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Failed to check system health',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
    ]);
}

// Función para verificar salud de la base de datos
function check_database_health() {
    try {
        $db = Database::getInstance()->getConnection();
        
        // Test de conexión
        $start = microtime(true);
        $stmt = $db->query("SELECT 1");
        $response_time = (microtime(true) - $start) * 1000; // ms
        
        // Verificar tablas críticas
        $critical_tables = ['users', 'sessions', 'devices', 'relay_status'];
        $missing_tables = [];
        
        foreach ($critical_tables as $table) {
            try {
                $db->query("SELECT 1 FROM $table LIMIT 1");
            } catch (Exception $e) {
                $missing_tables[] = $table;
            }
        }
        
        $status = 'healthy';
        $issues = [];
        
        if ($response_time > 100) {
            $status = 'warning';
            $issues[] = 'Slow response time: ' . round($response_time, 2) . 'ms';
        }
        
        if (!empty($missing_tables)) {
            $status = 'critical';
            $issues[] = 'Missing tables: ' . implode(', ', $missing_tables);
        }
        
        return [
            'status' => $status,
            'response_time' => round($response_time, 2) . 'ms',
            'issues' => $issues
        ];
        
    } catch (Exception $e) {
        return [
            'status' => 'critical',
            'error' => 'Database connection failed',
            'message' => $e->getMessage()
        ];
    }
}

// Función para verificar salud de sesiones
function check_session_health() {
    try {
        $db = Database::getInstance()->getConnection();
        
        // Contar sesiones activas
        $stmt = $db->query("SELECT COUNT(*) as active FROM sessions WHERE is_active = 1");
        $active = $stmt->fetch(PDO::FETCH_ASSOC)['active'];
        
        // Contar sesiones expiradas sin limpiar
        $stmt = $db->query("
            SELECT COUNT(*) as expired 
            FROM sessions 
            WHERE is_active = 1 
            AND last_activity < DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        $expired = $stmt->fetch(PDO::FETCH_ASSOC)['expired'];
        
        $status = 'healthy';
        $issues = [];
        
        if ($expired > 100) {
            $status = 'warning';
            $issues[] = 'High number of expired sessions: ' . $expired;
        }
        
        return [
            'status' => $status,
            'active_sessions' => (int)$active,
            'expired_sessions' => (int)$expired,
            'issues' => $issues
        ];
        
    } catch (Exception $e) {
        return [
            'status' => 'warning',
            'error' => 'Session check failed',
            'message' => $e->getMessage()
        ];
    }
}

// Función para verificar salud del relé
function check_relay_health() {
    try {
        $db = Database::getInstance()->getConnection();
        
        // Verificar último estado del relé
        $stmt = $db->query("
            SELECT *, TIMESTAMPDIFF(MINUTE, changed_at, NOW()) as minutes_ago
            FROM relay_status 
            ORDER BY changed_at DESC 
            LIMIT 1
        ");
        $last_status = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $status = 'healthy';
        $issues = [];
        
        if (!$last_status) {
            $status = 'warning';
            $issues[] = 'No relay status records found';
        } elseif ($last_status['minutes_ago'] > 1440) { // 24 horas
            $status = 'warning';
            $issues[] = 'No relay activity in 24 hours';
        }
        
        // Simular verificación GPIO (en producción sería real)
        $gpio_status = [
            'pin' => 23,
            'accessible' => true,
            'simulated' => true
        ];
        
        return [
            'status' => $status,
            'current_state' => $last_status ? $last_status['status'] : 'unknown',
            'last_change' => $last_status ? $last_status['changed_at'] : null,
            'gpio_status' => $gpio_status,
            'issues' => $issues
        ];
        
    } catch (Exception $e) {
        return [
            'status' => 'critical',
            'error' => 'Relay check failed',
            'message' => $e->getMessage()
        ];
    }
}

// Función para verificar salud del sistema de archivos
function check_filesystem_health() {
    try {
        $paths_to_check = [
            '/var/www/html/logs' => 'Log directory',
            '/var/www/html/images' => 'Images directory',
            '/var/www/html/includes' => 'Includes directory'
        ];
        
        $status = 'healthy';
        $issues = [];
        $disk_usage = [];
        
        foreach ($paths_to_check as $path => $name) {
            if (!is_dir($path)) {
                $status = 'warning';
                $issues[] = "$name not found: $path";
            } elseif (!is_writable($path)) {
                $status = 'warning';
                $issues[] = "$name not writable: $path";
            }
        }
        
        // Verificar espacio en disco
        $free_space = disk_free_space('/');
        $total_space = disk_total_space('/');
        $used_percentage = (($total_space - $free_space) / $total_space) * 100;
        
        if ($used_percentage > 90) {
            $status = 'critical';
            $issues[] = 'Disk usage critical: ' . round($used_percentage, 1) . '%';
        } elseif ($used_percentage > 80) {
            $status = 'warning';
            $issues[] = 'Disk usage warning: ' . round($used_percentage, 1) . '%';
        }
        
        return [
            'status' => $status,
            'disk_usage' => round($used_percentage, 1) . '%',
            'free_space' => format_bytes($free_space),
            'total_space' => format_bytes($total_space),
            'issues' => $issues
        ];
        
    } catch (Exception $e) {
        return [
            'status' => 'warning',
            'error' => 'Filesystem check failed',
            'message' => $e->getMessage()
        ];
    }
}

// Función para verificar salud del servidor web
function check_webserver_health() {
    try {
        $status = 'healthy';
        $issues = [];
        $info = [];
        
        // Verificar carga del sistema
        if (function_exists('sys_getloadavg')) {
            $load = sys_getloadavg();
            $info['load_average'] = [
                '1min' => round($load[0], 2),
                '5min' => round($load[1], 2),
                '15min' => round($load[2], 2)
            ];
            
            if ($load[0] > 4) {
                $status = 'critical';
                $issues[] = 'High system load: ' . $load[0];
            } elseif ($load[0] > 2) {
                $status = 'warning';
                $issues[] = 'Elevated system load: ' . $load[0];
            }
        }
        
        // Memoria disponible
        if (function_exists('memory_get_usage')) {
            $memory_usage = memory_get_usage(true);
            $memory_limit = ini_get('memory_limit');
            $info['memory'] = [
                'used' => format_bytes($memory_usage),
                'limit' => $memory_limit
            ];
        }
        
        return [
            'status' => $status,
            'info' => $info,
            'issues' => $issues
        ];
        
    } catch (Exception $e) {
        return [
            'status' => 'warning',
            'error' => 'Web server check failed',
            'message' => $e->getMessage()
        ];
    }
}

// Función auxiliar para formatear bytes
function format_bytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    
    $bytes /= pow(1024, $pow);
    
    return round($bytes, $precision) . ' ' . $units[$pow];
}
