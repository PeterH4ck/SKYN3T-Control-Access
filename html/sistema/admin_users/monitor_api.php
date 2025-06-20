<?php
/**
 * API DE MONITOREO DEL SISTEMA - SKYN3T
 * Proporciona métricas y datos de monitoreo en tiempo real
 * Versión: 3.0.1 - Solo para peterh4ck
 */

session_start();

require_once __DIR__ . '/../includes/database.php';
require_once __DIR__ . '/../includes/config.php';

header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');

// Verificar acceso EXCLUSIVO para peterh4ck
function checkMonitorAccess() {
    if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
        http_response_code(401);
        echo json_encode(['error' => 'No autorizado - Sesión no válida']);
        exit;
    }

    $username = $_SESSION['username'] ?? '';
    $role = $_SESSION['role'] ?? 'User';

    if ($username !== 'peterh4ck') {
        http_response_code(403);
        echo json_encode([
            'error' => 'Acceso DENEGADO - Monitoreo exclusivo para administrador principal',
            'attempted_user' => $username
        ]);
        
        error_log("UNAUTHORIZED MONITOR ACCESS: user=$username, ip=" . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        exit;
    }

    if ($role !== 'SuperUser') {
        http_response_code(403);
        echo json_encode(['error' => 'Permisos insuficientes para monitoreo del sistema']);
        exit;
    }

    return $username;
}

// Verificar acceso antes de procesar
$adminUser = checkMonitorAccess();

$action = $_GET['action'] ?? '';

try {
    $db = Database::getInstance();

    switch($action) {
        case 'system_metrics':
            getSystemMetrics($db);
            break;
        case 'system_alerts':
            getSystemAlerts($db);
            break;
        case 'recent_activity':
            getRecentActivity($db);
            break;
        case 'performance_data':
            getPerformanceData($db);
            break;
        case 'security_status':
            getSecurityStatus($db);
            break;
        case 'database_health':
            getDatabaseHealth($db);
            break;
        case 'system_resources':
            getSystemResources();
            break;
        case 'network_status':
            getNetworkStatus();
            break;
        case 'error_logs':
            getErrorLogs();
            break;
        case 'backup_status':
            getBackupStatus();
            break;
        case 'service_status':
            getServiceStatus();
            break;
        case 'disk_usage':
            getDiskUsage();
            break;
        default:
            http_response_code(400);
            echo json_encode([
                'error' => 'Acción no válida',
                'available_actions' => [
                    'system_metrics', 'system_alerts', 'recent_activity', 'performance_data',
                    'security_status', 'database_health', 'system_resources', 'network_status',
                    'error_logs', 'backup_status', 'service_status', 'disk_usage'
                ]
            ]);
    }
} catch (Exception $e) {
    error_log("Error en monitor_api.php: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Error interno del sistema de monitoreo',
        'message' => $e->getMessage(),
        'debug' => DEBUG_MODE ? $e->getTraceAsString() : null
    ]);
}

// Obtener métricas principales del sistema
function getSystemMetrics($db) {
    try {
        $metrics = [];

        // Carga del sistema (load average)
        if (function_exists('sys_getloadavg')) {
            $load = sys_getloadavg();
            $metrics['system_load'] = round($load[0] * 100 / 4, 2); // Asumiendo 4 cores
        } else {
            $metrics['system_load'] = 0;
        }

        // Uso de memoria
        $memInfo = getMemoryInfo();
        $metrics['memory_usage'] = $memInfo['usage_percent'];
        $metrics['memory_total'] = $memInfo['total'];
        $metrics['memory_used'] = $memInfo['used'];
        $metrics['memory_free'] = $memInfo['free'];

        // Conexiones a la base de datos
        try {
            $stmt = $db->execute("SHOW STATUS LIKE 'Threads_connected'");
            $result = $stmt->fetch();
            $metrics['db_connections'] = (int)($result['Value'] ?? 0);
        } catch (Exception $e) {
            $metrics['db_connections'] = 0;
        }

        // Sesiones activas
        try {
            $stmt = $db->execute("SELECT COUNT(*) as count FROM sessions WHERE expires_at > NOW()");
            $result = $stmt->fetch();
            $metrics['active_sessions'] = (int)($result['count'] ?? 0);
        } catch (Exception $e) {
            $metrics['active_sessions'] = 0;
        }

        // Usuarios únicos activos (últimas 24h)
        try {
            if ($db->tableExists('access_log')) {
                $stmt = $db->execute("SELECT COUNT(DISTINCT user_id) as count FROM access_log WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
                $result = $stmt->fetch();
                $metrics['active_users_24h'] = (int)($result['count'] ?? 0);
            } else {
                $metrics['active_users_24h'] = 0;
            }
        } catch (Exception $e) {
            $metrics['active_users_24h'] = 0;
        }

        // Uso de disco
        $diskInfo = getDiskInfo();
        $metrics['disk_usage'] = $diskInfo['usage_percent'];
        $metrics['disk_free'] = $diskInfo['free'];
        $metrics['disk_total'] = $diskInfo['total'];

        // Estadísticas de PHP
        $metrics['php_memory_usage'] = round(memory_get_usage(true) / 1024 / 1024, 2); // MB
        $metrics['php_memory_peak'] = round(memory_get_peak_usage(true) / 1024 / 1024, 2); // MB

        // Tiempo de respuesta de la base de datos
        $start_time = microtime(true);
        $db->execute("SELECT 1");
        $metrics['db_response_time'] = round((microtime(true) - $start_time) * 1000, 2); // ms

        // Procesos de Apache/PHP
        $metrics['apache_processes'] = getApacheProcessCount();

        // Última vez que se ejecutó un backup
        $metrics['last_backup'] = getLastBackupTime();

        // Errores recientes
        $metrics['recent_errors'] = getRecentErrorCount();

        echo json_encode([
            'success' => true,
            'metrics' => $metrics,
            'timestamp' => date('Y-m-d H:i:s'),
            'server_time' => time()
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al obtener métricas: ' . $e->getMessage()
        ]);
    }
}

// Obtener información de memoria
function getMemoryInfo() {
    $memInfo = [];
    
    if (file_exists('/proc/meminfo')) {
        $data = file_get_contents('/proc/meminfo');
        preg_match_all('/(\w+):\s+(\d+)\s+kB/', $data, $matches);
        
        $info = array_combine($matches[1], $matches[2]);
        
        $total = (int)($info['MemTotal'] ?? 0) * 1024; // Convertir a bytes
        $free = (int)($info['MemFree'] ?? 0) * 1024;
        $available = (int)($info['MemAvailable'] ?? $free) * 1024;
        $used = $total - $available;
        
        $memInfo = [
            'total' => $total,
            'used' => $used,
            'free' => $available,
            'usage_percent' => $total > 0 ? round(($used / $total) * 100, 2) : 0
        ];
    } else {
        // Fallback para sistemas sin /proc/meminfo
        $memInfo = [
            'total' => 0,
            'used' => memory_get_usage(true),
            'free' => 0,
            'usage_percent' => 0
        ];
    }
    
    return $memInfo;
}

// Obtener información de disco
function getDiskInfo() {
    $path = '/var/www/html';
    
    $total = disk_total_space($path);
    $free = disk_free_space($path);
    $used = $total - $free;
    
    return [
        'total' => $total,
        'used' => $used,
        'free' => $free,
        'usage_percent' => $total > 0 ? round(($used / $total) * 100, 2) : 0
    ];
}

// Obtener número de procesos de Apache
function getApacheProcessCount() {
    $output = shell_exec('ps aux | grep apache2 | grep -v grep | wc -l');
    return (int)trim($output);
}

// Obtener tiempo del último backup
function getLastBackupTime() {
    $backupDir = '/var/www/html/backups/';
    if (!is_dir($backupDir)) {
        return null;
    }
    
    $files = glob($backupDir . '*.sql');
    $files = array_merge($files, glob($backupDir . '*.tar.gz'));
    
    if (empty($files)) {
        return null;
    }
    
    $latest = 0;
    foreach ($files as $file) {
        $latest = max($latest, filemtime($file));
    }
    
    return $latest > 0 ? date('Y-m-d H:i:s', $latest) : null;
}

// Obtener número de errores recientes
function getRecentErrorCount() {
    $logFile = '/var/log/apache2/error.log';
    if (!file_exists($logFile)) {
        return 0;
    }
    
    $since = date('Y-m-d H:i:s', time() - 3600); // Última hora
    $command = "grep -c '".date('Y-m-d H:')."' $logFile 2>/dev/null || echo 0";
    $count = (int)trim(shell_exec($command));
    
    return $count;
}

// Obtener alertas del sistema
function getSystemAlerts($db) {
    try {
        $alerts = [];
        
        // Verificar uso de memoria
        $memInfo = getMemoryInfo();
        if ($memInfo['usage_percent'] > 85) {
            $alerts[] = [
                'level' => 'critical',
                'message' => "Uso de memoria crítico: {$memInfo['usage_percent']}%",
                'timestamp' => date('H:i:s'),
                'category' => 'system'
            ];
        } elseif ($memInfo['usage_percent'] > 70) {
            $alerts[] = [
                'level' => 'warning',
                'message' => "Uso de memoria alto: {$memInfo['usage_percent']}%",
                'timestamp' => date('H:i:s'),
                'category' => 'system'
            ];
        }
        
        // Verificar uso de disco
        $diskInfo = getDiskInfo();
        if ($diskInfo['usage_percent'] > 90) {
            $alerts[] = [
                'level' => 'critical',
                'message' => "Espacio en disco crítico: {$diskInfo['usage_percent']}%",
                'timestamp' => date('H:i:s'),
                'category' => 'storage'
            ];
        } elseif ($diskInfo['usage_percent'] > 80) {
            $alerts[] = [
                'level' => 'warning',
                'message' => "Espacio en disco bajo: {$diskInfo['usage_percent']}%",
                'timestamp' => date('H:i:s'),
                'category' => 'storage'
            ];
        }
        
        // Verificar conexiones a la base de datos
        try {
            $stmt = $db->execute("SHOW STATUS LIKE 'Threads_connected'");
            $result = $stmt->fetch();
            $connections = (int)($result['Value'] ?? 0);
            
            if ($connections > 100) {
                $alerts[] = [
                    'level' => 'warning',
                    'message' => "Muchas conexiones a BD: $connections",
                    'timestamp' => date('H:i:s'),
                    'category' => 'database'
                ];
            }
        } catch (Exception $e) {
            $alerts[] = [
                'level' => 'error',
                'message' => "Error verificando conexiones BD: " . $e->getMessage(),
                'timestamp' => date('H:i:s'),
                'category' => 'database'
            ];
        }
        
        // Verificar intentos de login fallidos recientes
        try {
            if ($db->tableExists('access_log')) {
                $stmt = $db->execute("SELECT COUNT(*) as count FROM access_log WHERE action = 'login_failed' AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)");
                $result = $stmt->fetch();
                $failedLogins = (int)($result['count'] ?? 0);
                
                if ($failedLogins > 10) {
                    $alerts[] = [
                        'level' => 'warning',
                        'message' => "Múltiples intentos de login fallidos: $failedLogins en la última hora",
                        'timestamp' => date('H:i:s'),
                        'category' => 'security'
                    ];
                }
            }
        } catch (Exception $e) {
            // Ignorar errores de logs
        }
        
        // Verificar servicios críticos
        $services = ['apache2', 'mysql', 'mariadb'];
        foreach ($services as $service) {
            if (!isServiceRunning($service)) {
                $alerts[] = [
                    'level' => 'critical',
                    'message' => "Servicio '$service' no está ejecutándose",
                    'timestamp' => date('H:i:s'),
                    'category' => 'services'
                ];
            }
        }
        
        echo json_encode([
            'success' => true,
            'alerts' => $alerts,
            'total_alerts' => count($alerts),
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al obtener alertas: ' . $e->getMessage()
        ]);
    }
}

// Verificar si un servicio está ejecutándose
function isServiceRunning($service) {
    $output = shell_exec("systemctl is-active $service 2>/dev/null");
    return trim($output) === 'active';
}

// Obtener actividad reciente
function getRecentActivity($db) {
    try {
        $activities = [];
        
        // Obtener actividad de access_log si existe
        if ($db->tableExists('access_log')) {
            $stmt = $db->execute("
                SELECT 
                    action,
                    username,
                    ip_address,
                    timestamp,
                    user_agent
                FROM access_log 
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
                ORDER BY timestamp DESC 
                LIMIT 20
            ");
            
            $logs = $stmt->fetchAll();
            
            foreach ($logs as $log) {
                $activities[] = [
                    'action' => $log['action'],
                    'username' => $log['username'],
                    'description' => formatActivityDescription($log['action'], $log['username']),
                    'timestamp' => $log['timestamp'],
                    'ip_address' => $log['ip_address'],
                    'type' => getActivityType($log['action'])
                ];
            }
        }
        
        // Agregar actividad del sistema
        $systemActivities = getSystemActivity();
        $activities = array_merge($activities, $systemActivities);
        
        // Ordenar por timestamp
        usort($activities, function($a, $b) {
            return strtotime($b['timestamp']) - strtotime($a['timestamp']);
        });
        
        // Limitar a 30 actividades
        $activities = array_slice($activities, 0, 30);
        
        echo json_encode([
            'success' => true,
            'activities' => $activities,
            'total' => count($activities),
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al obtener actividad: ' . $e->getMessage()
        ]);
    }
}

// Formatear descripción de actividad
function formatActivityDescription($action, $username) {
    $descriptions = [
        'login_success' => "Usuario $username inició sesión exitosamente",
        'login_failed' => "Intento de login fallido para $username",
        'logout' => "Usuario $username cerró sesión",
        'user_created' => "Usuario $username creó una nueva cuenta",
        'user_updated' => "Usuario $username actualizó información",
        'user_deleted' => "Usuario $username eliminó una cuenta",
        'backup_created' => "Se creó un backup del sistema",
        'database_backup_created' => "Se creó un backup de la base de datos",
        'relay_control' => "Usuario $username controló el relé",
        'device_added' => "Se agregó un nuevo dispositivo",
        'config_changed' => "Se modificó la configuración del sistema"
    ];
    
    return $descriptions[$action] ?? "Acción: $action por $username";
}

// Obtener tipo de actividad
function getActivityType($action) {
    $types = [
        'login_success' => 'success',
        'login_failed' => 'error',
        'logout' => 'info',
        'user_created' => 'success',
        'user_updated' => 'info',
        'user_deleted' => 'warning',
        'backup_created' => 'success',
        'relay_control' => 'info',
        'config_changed' => 'warning'
    ];
    
    return $types[$action] ?? 'info';
}

// Obtener actividad del sistema
function getSystemActivity() {
    $activities = [];
    
    // Verificar reinicio del sistema
    $uptime = shell_exec('uptime -s 2>/dev/null');
    if ($uptime) {
        $bootTime = strtotime(trim($uptime));
        if ($bootTime > time() - 3600) { // Reiniciado en la última hora
            $activities[] = [
                'action' => 'system_restart',
                'username' => 'Sistema',
                'description' => 'El sistema se reinició',
                'timestamp' => date('Y-m-d H:i:s', $bootTime),
                'type' => 'warning'
            ];
        }
    }
    
    return $activities;
}

// Obtener datos de rendimiento
function getPerformanceData($db) {
    try {
        $performance = [
            'cpu' => getCPUUsage(),
            'memory' => getMemoryInfo(),
            'disk' => getDiskInfo(),
            'network' => getNetworkStats(),
            'database' => getDatabasePerformance($db),
            'php' => getPHPPerformance()
        ];
        
        echo json_encode([
            'success' => true,
            'performance' => $performance,
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al obtener datos de rendimiento: ' . $e->getMessage()
        ]);
    }
}

// Obtener uso de CPU
function getCPUUsage() {
    if (function_exists('sys_getloadavg')) {
        $load = sys_getloadavg();
        return [
            'load_1min' => $load[0],
            'load_5min' => $load[1],
            'load_15min' => $load[2],
            'usage_percent' => round($load[0] * 100 / 4, 2) // Asumiendo 4 cores
        ];
    }
    
    return [
        'load_1min' => 0,
        'load_5min' => 0,
        'load_15min' => 0,
        'usage_percent' => 0
    ];
}

// Obtener estadísticas de red
function getNetworkStats() {
    // Implementación básica - en un entorno real se obtendría de /proc/net/dev
    return [
        'bytes_received' => 0,
        'bytes_transmitted' => 0,
        'packets_received' => 0,
        'packets_transmitted' => 0
    ];
}

// Obtener rendimiento de la base de datos
function getDatabasePerformance($db) {
    try {
        $performance = [];
        
        // Número de consultas
        $stmt = $db->execute("SHOW STATUS LIKE 'Questions'");
        $result = $stmt->fetch();
        $performance['total_queries'] = (int)($result['Value'] ?? 0);
        
        // Consultas por segundo
        $stmt = $db->execute("SHOW STATUS LIKE 'Uptime'");
        $result = $stmt->fetch();
        $uptime = (int)($result['Value'] ?? 1);
        $performance['queries_per_second'] = round($performance['total_queries'] / $uptime, 2);
        
        // Conexiones
        $stmt = $db->execute("SHOW STATUS LIKE 'Threads_connected'");
        $result = $stmt->fetch();
        $performance['connections'] = (int)($result['Value'] ?? 0);
        
        // Tamaño de la base de datos
        $stmt = $db->execute("
            SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS size_mb 
            FROM information_schema.tables 
            WHERE table_schema = 'skyn3t_db'
        ");
        $result = $stmt->fetch();
        $performance['database_size_mb'] = (float)($result['size_mb'] ?? 0);
        
        return $performance;
        
    } catch (Exception $e) {
        return [
            'total_queries' => 0,
            'queries_per_second' => 0,
            'connections' => 0,
            'database_size_mb' => 0,
            'error' => $e->getMessage()
        ];
    }
}

// Obtener rendimiento de PHP
function getPHPPerformance() {
    return [
        'memory_usage_mb' => round(memory_get_usage(true) / 1024 / 1024, 2),
        'memory_peak_mb' => round(memory_get_peak_usage(true) / 1024 / 1024, 2),
        'memory_limit' => ini_get('memory_limit'),
        'max_execution_time' => ini_get('max_execution_time'),
        'version' => PHP_VERSION
    ];
}

// Obtener estado de seguridad
function getSecurityStatus($db) {
    try {
        $security = [
            'failed_logins_1h' => 0,
            'active_sessions' => 0,
            'suspicious_ips' => [],
            'last_backup' => getLastBackupTime(),
            'system_alerts' => 0
        ];
        
        // Intentos fallidos de login
        if ($db->tableExists('access_log')) {
            $stmt = $db->execute("
                SELECT COUNT(*) as count 
                FROM access_log 
                WHERE action = 'login_failed' 
                AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            ");
            $result = $stmt->fetch();
            $security['failed_logins_1h'] = (int)($result['count'] ?? 0);
            
            // IPs sospechosas (múltiples intentos fallidos)
            $stmt = $db->execute("
                SELECT ip_address, COUNT(*) as attempts 
                FROM access_log 
                WHERE action = 'login_failed' 
                AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY ip_address 
                HAVING attempts > 5
                ORDER BY attempts DESC
            ");
            $security['suspicious_ips'] = $stmt->fetchAll();
        }
        
        // Sesiones activas
        $stmt = $db->execute("SELECT COUNT(*) as count FROM sessions WHERE expires_at > NOW()");
        $result = $stmt->fetch();
        $security['active_sessions'] = (int)($result['count'] ?? 0);
        
        echo json_encode([
            'success' => true,
            'security' => $security,
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al obtener estado de seguridad: ' . $e->getMessage()
        ]);
    }
}

// Funciones adicionales para completar la API

function getDatabaseHealth($db) {
    echo json_encode([
        'success' => true,
        'health' => 'Función de salud de BD en desarrollo'
    ]);
}

function getSystemResources() {
    echo json_encode([
        'success' => true,
        'resources' => 'Función de recursos del sistema en desarrollo'
    ]);
}

function getNetworkStatus() {
    echo json_encode([
        'success' => true,
        'network' => 'Función de estado de red en desarrollo'
    ]);
}

function getErrorLogs() {
    echo json_encode([
        'success' => true,
        'logs' => 'Función de logs de error en desarrollo'
    ]);
}

function getBackupStatus() {
    echo json_encode([
        'success' => true,
        'backup_status' => 'Función de estado de backup en desarrollo'
    ]);
}

function getServiceStatus() {
    echo json_encode([
        'success' => true,
        'services' => 'Función de estado de servicios en desarrollo'
    ]);
}

function getDiskUsage() {
    echo json_encode([
        'success' => true,
        'disk_usage' => getDiskInfo()
    ]);
}
?>