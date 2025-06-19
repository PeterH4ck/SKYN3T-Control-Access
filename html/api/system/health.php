<?php
/**
 * Archivo: /var/www/html/api/system/health.php
 * API endpoint para verificar estado de salud del sistema
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

// Incluir sistema
require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/database.php';
require_once __DIR__ . '/../../includes/security.php';

try {
    $startTime = microtime(true);
    
    // Información general del sistema
    $health = [
        'status' => 'healthy',
        'timestamp' => date('Y-m-d H:i:s'),
        'version' => getConfig('SYSTEM_VERSION', '2.0.0'),
        'environment' => getConfig('ENVIRONMENT', 'development'),
        'components' => [],
        'metrics' => [],
        'alerts' => []
    ];
    
    // ================================================
    // VERIFICAR BASE DE DATOS
    // ================================================
    try {
        $db = Database::getInstance();
        $dbStart = microtime(true);
        
        // Test de conexión básico
        $connectionTest = $db->fetch("SELECT 1 as test");
        $dbResponseTime = (microtime(true) - $dbStart) * 1000;
        
        // Obtener información de la base de datos
        $dbInfo = $db->getDatabaseInfo();
        
        // Verificar tablas críticas
        $criticalTables = ['users', 'sessions', 'devices', 'relay_status', 'access_log'];
        $tablesStatus = [];
        
        foreach ($criticalTables as $table) {
            $tableExists = $db->tableExists($table);
            $tablesStatus[$table] = $tableExists;
            
            if (!$tableExists) {
                $health['alerts'][] = [
                    'level' => 'critical',
                    'component' => 'database',
                    'message' => "Tabla crítica '$table' no encontrada"
                ];
                $health['status'] = 'unhealthy';
            }
        }
        
        // Verificar rendimiento de la base de datos
        if ($dbResponseTime > 1000) { // > 1 segundo
            $health['alerts'][] = [
                'level' => 'warning',
                'component' => 'database',
                'message' => 'Tiempo de respuesta de base de datos alto: ' . round($dbResponseTime, 2) . 'ms'
            ];
            if ($health['status'] === 'healthy') {
                $health['status'] = 'degraded';
            }
        }
        
        $health['components']['database'] = [
            'status' => count($health['alerts']) == 0 ? 'healthy' : 'degraded',
            'response_time_ms' => round($dbResponseTime, 2),
            'version' => $dbInfo['version'],
            'connection_status' => $dbInfo['connection_status'],
            'tables_count' => $dbInfo['tables_count'],
            'critical_tables' => $tablesStatus
        ];
        
    } catch (Exception $e) {
        $health['components']['database'] = [
            'status' => 'unhealthy',
            'error' => $e->getMessage()
        ];
        $health['alerts'][] = [
            'level' => 'critical',
            'component' => 'database',
            'message' => 'Error de conexión: ' . $e->getMessage()
        ];
        $health['status'] = 'unhealthy';
    }
    
    // ================================================
    // VERIFICAR SISTEMA DE ARCHIVOS
    // ================================================
    $filesystemHealth = checkFilesystemHealth();
    $health['components']['filesystem'] = $filesystemHealth;
    
    if ($filesystemHealth['status'] !== 'healthy') {
        if ($health['status'] === 'healthy') {
            $health['status'] = 'degraded';
        }
        $health['alerts'] = array_merge($health['alerts'], $filesystemHealth['alerts'] ?? []);
    }
    
    // ================================================
    // VERIFICAR SESIONES
    // ================================================
    try {
        if (isset($db)) {
            $sessionStart = microtime(true);
            
            // Limpiar sesiones expiradas
            $expiredSessions = $db->update("DELETE FROM sessions WHERE expires_at < NOW()");
            
            // Contar sesiones activas
            $activeSessions = $db->fetch("SELECT COUNT(*) as count FROM sessions WHERE expires_at > NOW()");
            $sessionResponseTime = (microtime(true) - $sessionStart) * 1000;
            
            $health['components']['sessions'] = [
                'status' => 'healthy',
                'active_sessions' => (int)$activeSessions['count'],
                'expired_cleaned' => $expiredSessions,
                'response_time_ms' => round($sessionResponseTime, 2)
            ];
            
            // Alertar si hay demasiadas sesiones activas
            if ($activeSessions['count'] > 100) {
                $health['alerts'][] = [
                    'level' => 'warning',
                    'component' => 'sessions',
                    'message' => 'Alto número de sesiones activas: ' . $activeSessions['count']
                ];
                if ($health['status'] === 'healthy') {
                    $health['status'] = 'degraded';
                }
            }
        }
    } catch (Exception $e) {
        $health['components']['sessions'] = [
            'status' => 'unhealthy',
            'error' => $e->getMessage()
        ];
        $health['alerts'][] = [
            'level' => 'critical',
            'component' => 'sessions',
            'message' => 'Error en sistema de sesiones: ' . $e->getMessage()
        ];
        $health['status'] = 'unhealthy';
    }
    
    // ================================================
    // VERIFICAR CONTROL DE RELÉ
    // ================================================
    try {
        if (isset($db)) {
            $relayStart = microtime(true);
            
            // Verificar último estado del relé
            $lastRelayStatus = $db->fetch("
                SELECT relay_state, led_state, timestamp 
                FROM relay_status 
                ORDER BY timestamp DESC 
                LIMIT 1
            ");
            
            $relayResponseTime = (microtime(true) - $relayStart) * 1000;
            
            // Verificar GPIO (si está disponible)
            $gpioStatus = checkGPIOHealth();
            
            $health['components']['relay'] = [
                'status' => $gpioStatus['available'] ? 'healthy' : 'degraded',
                'last_state' => $lastRelayStatus ? [
                    'relay_on' => (bool)$lastRelayStatus['relay_state'],
                    'led_on' => (bool)$lastRelayStatus['led_state'],
                    'timestamp' => $lastRelayStatus['timestamp']
                ] : null,
                'gpio_available' => $gpioStatus['available'],
                'gpio_method' => $gpioStatus['method'],
                'response_time_ms' => round($relayResponseTime, 2)
            ];
            
            if (!$gpioStatus['available'] && getConfig('ENVIRONMENT') !== 'development') {
                $health['alerts'][] = [
                    'level' => 'warning',
                    'component' => 'relay',
                    'message' => 'GPIO no disponible para control físico del relé'
                ];
                if ($health['status'] === 'healthy') {
                    $health['status'] = 'degraded';
                }
            }
        }
    } catch (Exception $e) {
        $health['components']['relay'] = [
            'status' => 'unhealthy',
            'error' => $e->getMessage()
        ];
        $health['alerts'][] = [
            'level' => 'warning',
            'component' => 'relay',
            'message' => 'Error verificando relé: ' . $e->getMessage()
        ];
    }
    
    // ================================================
    // VERIFICAR LOGS Y SEGURIDAD
    // ================================================
    $logsHealth = checkLogsHealth();
    $health['components']['logs'] = $logsHealth;
    
    if ($logsHealth['status'] !== 'healthy') {
        $health['alerts'] = array_merge($health['alerts'], $logsHealth['alerts'] ?? []);
        if ($health['status'] === 'healthy') {
            $health['status'] = 'degraded';
        }
    }
    
    // ================================================
    // MÉTRICAS DEL SISTEMA
    // ================================================
    $health['metrics'] = [
        'memory_usage' => [
            'current' => memory_get_usage(true),
            'peak' => memory_get_peak_usage(true),
            'formatted' => [
                'current' => formatBytes(memory_get_usage(true)),
                'peak' => formatBytes(memory_get_peak_usage(true))
            ]
        ],
        'execution_time_ms' => round((microtime(true) - $startTime) * 1000, 2),
        'php_version' => PHP_VERSION,
        'server_load' => getServerLoad(),
        'disk_usage' => getDiskUsage()
    ];
    
    // ================================================
    // VERIFICACIONES ADICIONALES
    // ================================================
    
    // Verificar configuración crítica
    $configHealth = checkConfigurationHealth();
    if ($configHealth['issues']) {
        $health['alerts'] = array_merge($health['alerts'], $configHealth['alerts']);
        if ($health['status'] === 'healthy') {
            $health['status'] = 'degraded';
        }
    }
    
    // Establecer código de respuesta HTTP según el estado
    if ($health['status'] === 'unhealthy') {
        http_response_code(503); // Service Unavailable
    } elseif ($health['status'] === 'degraded') {
        http_response_code(200); // OK pero con advertencias
    } else {
        http_response_code(200); // OK
    }
    
    // Respuesta final
    echo json_encode($health, JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    error_log("Error en health check: " . $e->getMessage());
    
    http_response_code(500);
    echo json_encode([
        'status' => 'unhealthy',
        'timestamp' => date('Y-m-d H:i:s'),
        'error' => 'Health check failed',
        'message' => $e->getMessage()
    ]);
}

/**
 * Verificar salud del sistema de archivos
 */
function checkFilesystemHealth() {
    $health = [
        'status' => 'healthy',
        'alerts' => []
    ];
    
    // Verificar archivos críticos
    $criticalFiles = [
        '/var/www/html/includes/config.php',
        '/var/www/html/includes/database.php',
        '/var/www/html/includes/auth.php',
        '/var/www/html/includes/security.php',
        '/var/www/html/includes/session.php'
    ];
    
    $missingFiles = [];
    foreach ($criticalFiles as $file) {
        if (!file_exists($file)) {
            $missingFiles[] = basename($file);
        }
    }
    
    if (!empty($missingFiles)) {
        $health['status'] = 'unhealthy';
        $health['alerts'][] = [
            'level' => 'critical',
            'component' => 'filesystem',
            'message' => 'Archivos críticos faltantes: ' . implode(', ', $missingFiles)
        ];
    }
    
    // Verificar permisos de directorios
    $directories = [
        '/var/www/html/logs' => 'writable'
    ];
    
    foreach ($directories as $dir => $requirement) {
        if (!is_dir($dir)) {
            $health['alerts'][] = [
                'level' => 'warning',
                'component' => 'filesystem',
                'message' => "Directorio faltante: $dir"
            ];
            if ($health['status'] === 'healthy') {
                $health['status'] = 'degraded';
            }
        } elseif ($requirement === 'writable' && !is_writable($dir)) {
            $health['alerts'][] = [
                'level' => 'warning',
                'component' => 'filesystem',
                'message' => "Directorio sin permisos de escritura: $dir"
            ];
            if ($health['status'] === 'healthy') {
                $health['status'] = 'degraded';
            }
        }
    }
    
    return $health;
}

/**
 * Verificar estado del GPIO
 */
function checkGPIOHealth() {
    $relayPin = getConfig('RELAY_GPIO_PIN', 23);
    $ledPin = getConfig('LED_GPIO_PIN', 16);
    
    $status = [
        'available' => false,
        'method' => 'none',
        'pins' => [
            'relay' => $relayPin,
            'led' => $ledPin
        ]
    ];
    
    // Verificar si GPIO está disponible via sysfs
    if (is_dir('/sys/class/gpio')) {
        $status['available'] = true;
        $status['method'] = 'sysfs';
        
        // Verificar acceso a pines específicos
        $status['pins']['relay_accessible'] = is_dir("/sys/class/gpio/gpio$relayPin") || 
                                            is_writable('/sys/class/gpio/export');
        $status['pins']['led_accessible'] = is_dir("/sys/class/gpio/gpio$ledPin") || 
                                          is_writable('/sys/class/gpio/export');
    }
    
    // En modo desarrollo, simular disponibilidad
    if (getConfig('ENVIRONMENT') === 'development') {
        $status['available'] = true;
        $status['method'] = 'simulation';
    }
    
    return $status;
}

/**
 * Verificar salud de logs
 */
function checkLogsHealth() {
    $health = [
        'status' => 'healthy',
        'alerts' => []
    ];
    
    $logDir = '/var/www/html/logs';
    
    if (!is_dir($logDir)) {
        $health['status'] = 'degraded';
        $health['alerts'][] = [
            'level' => 'warning',
            'component' => 'logs',
            'message' => 'Directorio de logs no existe'
        ];
    } elseif (!is_writable($logDir)) {
        $health['status'] = 'degraded';
        $health['alerts'][] = [
            'level' => 'warning',
            'component' => 'logs',
            'message' => 'Directorio de logs sin permisos de escritura'
        ];
    }
    
    return $health;
}

/**
 * Verificar configuración crítica
 */
function checkConfigurationHealth() {
    $issues = [];
    $alerts = [];
    
    // Verificar configuraciones críticas
    if (!getConfig('DB_HOST')) {
        $issues[] = 'DB_HOST no configurado';
        $alerts[] = [
            'level' => 'critical',
            'component' => 'configuration',
            'message' => 'Configuración de base de datos incompleta'
        ];
    }
    
    if (getConfig('DEBUG_MODE') && getConfig('ENVIRONMENT') === 'production') {
        $issues[] = 'Debug mode activo en producción';
        $alerts[] = [
            'level' => 'warning',
            'component' => 'configuration',
            'message' => 'Modo debug activo en entorno de producción'
        ];
    }
    
    return [
        'issues' => !empty($issues),
        'alerts' => $alerts
    ];
}

/**
 * Obtener carga del servidor
 */
function getServerLoad() {
    if (function_exists('sys_getloadavg')) {
        $load = sys_getloadavg();
        return [
            '1min' => round($load[0], 2),
            '5min' => round($load[1], 2),
            '15min' => round($load[2], 2)
        ];
    }
    
    return null;
}

/**
 * Obtener uso de disco
 */
function getDiskUsage() {
    try {
        $bytes = disk_free_bytes('/var/www/html');
        $total = disk_total_space('/var/www/html');
        
        if ($bytes !== false && $total !== false) {
            $used = $total - $bytes;
            $percentage = round(($used / $total) * 100, 2);
            
            return [
                'total' => formatBytes($total),
                'used' => formatBytes($used),
                'free' => formatBytes($bytes),
                'percentage_used' => $percentage
            ];
        }
    } catch (Exception $e) {
        // Silenciar errores de disco
    }
    
    return null;
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
