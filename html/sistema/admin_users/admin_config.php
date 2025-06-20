<?php
/**
 * CONFIGURACIÓN AVANZADA DE LA PLATAFORMA DE ADMINISTRACIÓN - SKYN3T
 * Configuraciones específicas para el sistema de administración total
 * Versión: 3.0.1 - Solo para peterh4ck
 */

// Verificar acceso exclusivo
session_start();
if (!isset($_SESSION['username']) || $_SESSION['username'] !== 'peterh4ck') {
    header('HTTP/1.1 403 Forbidden');
    exit('Acceso denegado');
}

// Configuraciones de la plataforma de administración
class AdminConfig {
    
    // Configuraciones de seguridad
    const SECURITY_CONFIG = [
        'max_login_attempts' => 3,
        'lockout_duration' => 900, // 15 minutos
        'session_timeout' => 28800, // 8 horas
        'force_https' => false, // Cambiar a true en producción
        'csrf_protection' => true,
        'ip_whitelist' => [], // IPs permitidas (vacío = todas)
        'require_2fa' => false, // Autenticación de dos factores
        'log_all_actions' => true,
        'encrypt_sensitive_data' => true
    ];
    
    // Configuraciones de monitoreo
    const MONITORING_CONFIG = [
        'enable_realtime_monitoring' => true,
        'monitoring_interval' => 30, // segundos
        'alert_thresholds' => [
            'cpu_usage' => 80,
            'memory_usage' => 85,
            'disk_usage' => 90,
            'db_connections' => 100,
            'failed_logins_per_hour' => 10,
            'session_limit' => 50
        ],
        'alert_email' => '', // Email para alertas críticas
        'store_metrics_days' => 30,
        'performance_logging' => true
    ];
    
    // Configuraciones de backup
    const BACKUP_CONFIG = [
        'auto_backup_enabled' => true,
        'backup_frequency' => 'daily', // daily, weekly, monthly
        'backup_time' => '02:00', // Hora del backup automático
        'max_backups' => 50,
        'retention_days' => 30,
        'compress_backups' => true,
        'include_logs' => false,
        'backup_location' => '/var/www/html/backups/',
        'remote_backup' => false,
        'remote_backup_config' => [
            'type' => 'ftp', // ftp, sftp, s3
            'host' => '',
            'username' => '',
            'password' => '',
            'path' => ''
        ]
    ];
    
    // Configuraciones de base de datos
    const DATABASE_CONFIG = [
        'enable_query_logging' => true,
        'slow_query_threshold' => 1.0, // segundos
        'max_connections' => 100,
        'connection_timeout' => 30,
        'enable_profiling' => false,
        'optimize_tables' => true,
        'optimize_frequency' => 'weekly'
    ];
    
    // Configuraciones de logging
    const LOGGING_CONFIG = [
        'log_level' => 'INFO', // DEBUG, INFO, WARNING, ERROR, CRITICAL
        'log_file' => '/var/www/html/logs/admin_platform.log',
        'max_log_size' => 10485760, // 10MB
        'log_rotation' => true,
        'log_retention_days' => 90,
        'log_format' => '[{timestamp}] {level} {user} {action} {details}',
        'log_sensitive_data' => false,
        'separate_error_log' => true
    ];
    
    // Configuraciones de la interfaz
    const UI_CONFIG = [
        'theme' => 'dark', // dark, light
        'language' => 'es',
        'timezone' => 'America/Santiago',
        'date_format' => 'Y-m-d H:i:s',
        'items_per_page' => 25,
        'enable_animations' => true,
        'auto_refresh_interval' => 60, // segundos
        'keyboard_shortcuts' => true,
        'show_advanced_features' => true
    ];
    
    // Configuraciones de notificaciones
    const NOTIFICATION_CONFIG = [
        'enable_notifications' => true,
        'notification_methods' => ['browser', 'email'],
        'email_notifications' => [
            'smtp_host' => '',
            'smtp_port' => 587,
            'smtp_username' => '',
            'smtp_password' => '',
            'from_email' => 'admin@skyn3t.local',
            'from_name' => 'SKYN3T Admin'
        ],
        'browser_notifications' => [
            'enable_sound' => true,
            'show_desktop_notifications' => true,
            'notification_timeout' => 5000
        ]
    ];
    
    // Configuraciones de mantenimiento
    const MAINTENANCE_CONFIG = [
        'maintenance_mode' => false,
        'maintenance_message' => 'Sistema en mantenimiento. Vuelva más tarde.',
        'maintenance_allowed_ips' => ['192.168.4.1'],
        'auto_maintenance_window' => [
            'enabled' => false,
            'start_time' => '02:00',
            'end_time' => '04:00',
            'days' => ['sunday']
        ],
        'system_health_checks' => true,
        'auto_cleanup' => true,
        'cleanup_schedule' => 'daily'
    ];
    
    // Rutas y directorios
    const PATHS = [
        'admin_root' => '/var/www/html/sistema/admin_users/',
        'logs_dir' => '/var/www/html/logs/',
        'backups_dir' => '/var/www/html/backups/',
        'temp_dir' => '/tmp/skyn3t/',
        'uploads_dir' => '/var/www/html/uploads/',
        'scripts_dir' => '/var/www/html/scripts/'
    ];
    
    // URLs del sistema
    const URLS = [
        'base_url' => 'http://192.168.4.1',
        'admin_url' => 'http://192.168.4.1/sistema/admin_users/',
        'api_url' => 'http://192.168.4.1/sistema/admin_users/admin_api.php',
        'monitor_url' => 'http://192.168.4.1/sistema/admin_users/monitor_api.php',
        'backup_url' => 'http://192.168.4.1/sistema/admin_users/backup_system.php'
    ];
    
    // Información de la plataforma
    const PLATFORM_INFO = [
        'name' => 'SKYN3T Admin Platform',
        'version' => '3.0.1',
        'build' => '20250619',
        'author' => 'SKYN3T Systems',
        'exclusive_user' => 'peterh4ck',
        'description' => 'Plataforma de administración total del sistema SKYN3T',
        'features' => [
            'Gestión completa de usuarios',
            'Control total de base de datos',
            'Monitoreo en tiempo real',
            'Sistema de backup avanzado',
            'Herramientas de mantenimiento',
            'Consola SQL directa',
            'Alertas de seguridad',
            'Estadísticas del sistema'
        ]
    ];
    
    // Obtener configuración específica
    public static function get($section, $key = null) {
        $config = constant("self::{$section}_CONFIG");
        
        if ($key === null) {
            return $config;
        }
        
        return $config[$key] ?? null;
    }
    
    // Establecer configuración
    public static function set($section, $key, $value) {
        // En una implementación real, esto guardaría en base de datos
        // Por ahora solo validamos que sea una sección válida
        $validSections = [
            'SECURITY', 'MONITORING', 'BACKUP', 'DATABASE', 
            'LOGGING', 'UI', 'NOTIFICATION', 'MAINTENANCE'
        ];
        
        if (!in_array($section, $validSections)) {
            throw new Exception("Sección de configuración no válida: $section");
        }
        
        return true;
    }
    
    // Validar configuración del sistema
    public static function validateSystemConfig() {
        $issues = [];
        
        // Verificar directorios
        foreach (self::PATHS as $name => $path) {
            if (!is_dir($path) && !mkdir($path, 0755, true)) {
                $issues[] = "No se puede crear/acceder al directorio: $path ($name)";
            }
        }
        
        // Verificar permisos de escritura
        $writableDirs = ['logs_dir', 'backups_dir', 'temp_dir'];
        foreach ($writableDirs as $dir) {
            $path = self::PATHS[$dir];
            if (!is_writable($path)) {
                $issues[] = "Directorio sin permisos de escritura: $path ($dir)";
            }
        }
        
        // Verificar conexión a base de datos
        try {
            $db = Database::getInstance();
            $db->execute("SELECT 1");
        } catch (Exception $e) {
            $issues[] = "Error de conexión a base de datos: " . $e->getMessage();
        }
        
        // Verificar comandos del sistema
        $requiredCommands = ['mysqldump', 'mysql', 'tar', 'gzip'];
        foreach ($requiredCommands as $cmd) {
            if (!shell_exec("which $cmd")) {
                $issues[] = "Comando requerido no encontrado: $cmd";
            }
        }
        
        // Verificar límites de PHP
        $requiredMemory = 128 * 1024 * 1024; // 128MB
        $currentMemory = ini_get('memory_limit');
        if ($currentMemory !== '-1') {
            $memoryBytes = self::parseMemoryLimit($currentMemory);
            if ($memoryBytes < $requiredMemory) {
                $issues[] = "Límite de memoria PHP insuficiente: $currentMemory (requerido: 128M)";
            }
        }
        
        return [
            'valid' => empty($issues),
            'issues' => $issues,
            'warnings' => self::getConfigWarnings()
        ];
    }
    
    // Obtener advertencias de configuración
    private static function getConfigWarnings() {
        $warnings = [];
        
        // Verificar configuraciones de seguridad
        if (!self::SECURITY_CONFIG['force_https']) {
            $warnings[] = "HTTPS no está forzado (recomendado para producción)";
        }
        
        if (!self::SECURITY_CONFIG['require_2fa']) {
            $warnings[] = "Autenticación de dos factores deshabilitada";
        }
        
        if (empty(self::SECURITY_CONFIG['ip_whitelist'])) {
            $warnings[] = "Lista blanca de IPs vacía (cualquier IP puede intentar acceder)";
        }
        
        // Verificar configuraciones de backup
        if (!self::BACKUP_CONFIG['auto_backup_enabled']) {
            $warnings[] = "Backup automático deshabilitado";
        }
        
        if (!self::BACKUP_CONFIG['remote_backup']) {
            $warnings[] = "Backup remoto deshabilitado";
        }
        
        return $warnings;
    }
    
    // Parsear límite de memoria
    private static function parseMemoryLimit($limit) {
        $limit = strtolower($limit);
        $bytes = (int)$limit;
        
        if (strpos($limit, 'k') !== false) {
            $bytes *= 1024;
        } elseif (strpos($limit, 'm') !== false) {
            $bytes *= 1024 * 1024;
        } elseif (strpos($limit, 'g') !== false) {
            $bytes *= 1024 * 1024 * 1024;
        }
        
        return $bytes;
    }
    
    // Exportar configuración completa
    public static function exportConfig() {
        return [
            'platform_info' => self::PLATFORM_INFO,
            'security' => self::SECURITY_CONFIG,
            'monitoring' => self::MONITORING_CONFIG,
            'backup' => self::BACKUP_CONFIG,
            'database' => self::DATABASE_CONFIG,
            'logging' => self::LOGGING_CONFIG,
            'ui' => self::UI_CONFIG,
            'notification' => self::NOTIFICATION_CONFIG,
            'maintenance' => self::MAINTENANCE_CONFIG,
            'paths' => self::PATHS,
            'urls' => self::URLS,
            'exported_at' => date('Y-m-d H:i:s'),
            'exported_by' => $_SESSION['username'] ?? 'unknown'
        ];
    }
    
    // Generar hash de configuración para detectar cambios
    public static function getConfigHash() {
        return md5(json_encode(self::exportConfig()));
    }
    
    // Verificar integridad de la configuración
    public static function verifyConfigIntegrity() {
        $issues = [];
        
        // Verificar que todas las constantes estén definidas
        $requiredConstants = [
            'SECURITY_CONFIG', 'MONITORING_CONFIG', 'BACKUP_CONFIG',
            'DATABASE_CONFIG', 'LOGGING_CONFIG', 'UI_CONFIG',
            'NOTIFICATION_CONFIG', 'MAINTENANCE_CONFIG', 'PATHS', 'URLS'
        ];
        
        foreach ($requiredConstants as $constant) {
            if (!defined("self::$constant")) {
                $issues[] = "Configuración faltante: $constant";
            }
        }
        
        // Verificar valores críticos
        if (self::SECURITY_CONFIG['session_timeout'] < 300) {
            $issues[] = "Timeout de sesión muy bajo (mínimo 5 minutos)";
        }
        
        if (self::MONITORING_CONFIG['monitoring_interval'] < 10) {
            $issues[] = "Intervalo de monitoreo muy bajo (mínimo 10 segundos)";
        }
        
        return [
            'valid' => empty($issues),
            'issues' => $issues
        ];
    }
    
    // Obtener información del entorno
    public static function getEnvironmentInfo() {
        return [
            'php_version' => PHP_VERSION,
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
            'server_name' => $_SERVER['SERVER_NAME'] ?? 'unknown',
            'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? 'unknown',
            'server_admin' => $_SERVER['SERVER_ADMIN'] ?? 'unknown',
            'server_signature' => $_SERVER['SERVER_SIGNATURE'] ?? 'unknown',
            'request_time' => $_SERVER['REQUEST_TIME'] ?? time(),
            'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'system_load' => function_exists('sys_getloadavg') ? sys_getloadavg() : [0, 0, 0],
            'memory_usage' => [
                'current' => memory_get_usage(true),
                'peak' => memory_get_peak_usage(true),
                'limit' => ini_get('memory_limit')
            ],
            'disk_space' => [
                'free' => disk_free_space('/var/www/html'),
                'total' => disk_total_space('/var/www/html')
            ]
        ];
    }
    
    // Logs específicos de configuración
    public static function logConfigAction($action, $details = '') {
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'user' => $_SESSION['username'] ?? 'system',
            'action' => $action,
            'details' => $details,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ];
        
        $logFile = self::LOGGING_CONFIG['log_file'];
        $logDir = dirname($logFile);
        
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        
        $logLine = json_encode($logEntry) . "\n";
        file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
    }
}

// Funciones de ayuda para la configuración

/**
 * Obtener configuración específica
 */
function getAdminConfig($section, $key = null) {
    return AdminConfig::get($section, $key);
}

/**
 * Verificar si la plataforma está en modo mantenimiento
 */
function isMaintenanceMode() {
    $config = AdminConfig::get('MAINTENANCE', 'maintenance_mode');
    $allowedIPs = AdminConfig::get('MAINTENANCE', 'maintenance_allowed_ips');
    $currentIP = $_SERVER['REMOTE_ADDR'] ?? '';
    
    return $config && !in_array($currentIP, $allowedIPs);
}

/**
 * Verificar si el usuario actual tiene acceso a la función
 */
function hasAdminAccess($feature = null) {
    if (!isset($_SESSION['username']) || $_SESSION['username'] !== 'peterh4ck') {
        return false;
    }
    
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'SuperUser') {
        return false;
    }
    
    // Verificar funciones específicas si se proporciona
    if ($feature) {
        $disabledFeatures = AdminConfig::get('SECURITY', 'disabled_features') ?? [];
        return !in_array($feature, $disabledFeatures);
    }
    
    return true;
}

/**
 * Formatear tamaño de archivo
 */
function formatBytes($size, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    
    for ($i = 0; $size > 1024 && $i < count($units) - 1; $i++) {
        $size /= 1024;
    }
    
    return round($size, $precision) . ' ' . $units[$i];
}

/**
 * Obtener color de estado basado en porcentaje
 */
function getStatusColor($percentage) {
    if ($percentage >= 90) return '#dc3545'; // Rojo
    if ($percentage >= 75) return '#ffc107'; // Amarillo
    if ($percentage >= 50) return '#fd7e14'; // Naranja
    return '#28a745'; // Verde
}

/**
 * Verificar si un comando existe en el sistema
 */
function commandExists($command) {
    $output = shell_exec("which $command 2>/dev/null");
    return !empty($output);
}

/**
 * Generar token seguro
 */
function generateSecureToken($length = 32) {
    return bin2hex(random_bytes($length / 2));
}

// Inicialización automática cuando se incluye el archivo
if (!defined('ADMIN_CONFIG_LOADED')) {
    define('ADMIN_CONFIG_LOADED', true);
    
    // Verificar integridad de la configuración al cargar
    $integrity = AdminConfig::verifyConfigIntegrity();
    if (!$integrity['valid']) {
        error_log("ADMIN CONFIG ERROR: " . implode(', ', $integrity['issues']));
    }
    
    // Log de carga de configuración
    AdminConfig::logConfigAction('config_loaded', 'Configuración de administración cargada');
}
?>