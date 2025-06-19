<?php
/**
 * SKYN3T - Sistema de Control y Monitoreo
 * Archivo de configuración central
 * 
 * @version 2.0.0
 * @date 2025-01-19
 */

// Prevenir acceso directo
if (!defined('SKYN3T_SECURE')) {
    define('SKYN3T_SECURE', true);
}

// ===========================
// CONFIGURACIÓN DEL SISTEMA
// ===========================

// Información del sistema
define('SYSTEM_NAME', 'SKYN3T');
define('SYSTEM_VERSION', '2.0.0');
define('SYSTEM_DESCRIPTION', 'Sistema de Control y Monitoreo');
define('COMPANY_NAME', 'SKYN3T - IT & NETWORK SOLUTIONS');

// Entorno
define('ENVIRONMENT', 'development'); // development | production
define('DEBUG_MODE', ENVIRONMENT === 'development');

// URLs base
define('BASE_URL', 'http://192.168.4.1');
define('API_URL', BASE_URL . '/api');
define('ASSETS_URL', BASE_URL . '/assets');
define('IMAGES_URL', BASE_URL . '/images');

// Directorios
define('ROOT_PATH', '/var/www/html');
define('INCLUDES_PATH', ROOT_PATH . '/includes');
define('API_PATH', ROOT_PATH . '/api');
define('LOG_PATH', ROOT_PATH . '/logs');
define('TEMP_PATH', '/tmp');

// Base de datos
define('DB_HOST', 'localhost');
define('DB_NAME', 'skyn3t_db');
define('DB_USER', 'skyn3t_app');
define('DB_PASS', 'Skyn3t2025!');
define('DB_CHARSET', 'utf8mb4');

// Tablas principales (nombres actuales en la DB)
define('TABLE_USERS', 'users');
define('TABLE_SESSIONS', 'sessions');
define('TABLE_ACCESS_LOG', 'access_log');
define('TABLE_DEVICES', 'devices');
define('TABLE_RELAY_STATUS', 'relay_status'); // Tabla principal del relé
define('TABLE_NOTIFICATIONS', 'notifications');
define('TABLE_RESIDENTES', 'residentes');
define('TABLE_SYSTEM_CONFIG', 'system_config');

// Configuración de sesiones
define('SESSION_LIFETIME', 1440); // 24 horas en minutos
define('SESSION_REMEMBER_LIFETIME', 43200); // 30 días en minutos
define('SESSION_REGENERATE_TIME', 300); // 5 minutos
define('SESSION_MAX_ATTEMPTS', 5); // Intentos máximos de login
define('SESSION_LOCKOUT_TIME', 900); // 15 minutos de bloqueo

// Configuración de seguridad
define('PASSWORD_MIN_LENGTH', 8);
define('PASSWORD_BCRYPT_COST', 12);
define('ENCRYPTION_KEY', 'tu_clave_segura_aqui_32_caracteres!!'); // Cambiar en producción
define('CSRF_TOKEN_LENGTH', 32);

// Configuración de GPIO (Raspberry Pi)
define('GPIO_RELAY_PIN', 23);   // GPIO23 para el relé
define('GPIO_LED_PIN', 16);     // GPIO16 para el LED
define('GPIO_BUTTON_PIN', 25);  // GPIO25 para el botón

// Configuración de logs
define('LOG_ERRORS', true);
define('LOG_ACCESS', true);
define('LOG_SECURITY', true);
define('LOG_DEBUG', DEBUG_MODE);
define('LOG_MAX_SIZE', 10485760); // 10MB
define('LOG_ROTATION', true);

// Rate limiting
define('RATE_LIMIT_ENABLED', true);
define('RATE_LIMIT_REQUESTS', 60); // Requests por minuto
define('RATE_LIMIT_WINDOW', 60); // Ventana en segundos

// Roles del sistema (jerarquía)
define('ROLE_SUPERUSER', 'SuperUser');
define('ROLE_ADMIN', 'Admin');
define('ROLE_SUPPORT', 'SupportAdmin');
define('ROLE_USER', 'User');

// Niveles de permisos
$PERMISSION_LEVELS = [
    ROLE_SUPERUSER => 4,
    ROLE_ADMIN => 3,
    ROLE_SUPPORT => 2,
    ROLE_USER => 1
];

// Permisos por rol
$ROLE_PERMISSIONS = [
    ROLE_SUPERUSER => [
        'all' => true,
        'dashboard' => true,
        'devices' => true,
        'users' => true,
        'relay' => true,
        'logs' => true,
        'system' => true,
        'residentes' => true,
        'privileges' => true
    ],
    ROLE_ADMIN => [
        'dashboard' => true,
        'devices' => true,
        'users' => true,
        'relay' => true,
        'logs' => true,
        'residentes' => true
    ],
    ROLE_SUPPORT => [
        'dashboard' => true,
        'devices_view' => true,
        'relay_view' => true,
        'logs_view' => true,
        'residentes_view' => true
    ],
    ROLE_USER => [
        'dashboard_basic' => true,
        'profile' => true,
        'input_data' => true
    ]
];

// Configuración de notificaciones
define('NOTIFICATIONS_ENABLED', true);
define('NOTIFICATIONS_EMAIL', false); // Por ahora deshabilitado
define('NOTIFICATIONS_RETENTION', 30); // Días

// Configuración de API
define('API_VERSION', '2.0.0');
define('API_RATE_LIMIT', 1000); // Requests por hora
define('API_TIMEOUT', 30); // Segundos

// Configuración de interfaz
define('UI_THEME', 'dark');
define('UI_LANGUAGE', 'es');
define('UI_TIMEZONE', 'America/Santiago');
define('UI_DATE_FORMAT', 'Y-m-d H:i:s');

// Estados del relé (según estructura actual de DB)
define('RELAY_STATE_ON', 1);
define('RELAY_STATE_OFF', 0);
define('LED_STATE_ON', 1);
define('LED_STATE_OFF', 0);

// Métodos de cambio del relé
define('RELAY_CHANGE_WEB', 'web');
define('RELAY_CHANGE_BUTTON', 'button');
define('RELAY_CHANGE_SCREEN', 'screen');
define('RELAY_CHANGE_SCHEDULE', 'schedule');
define('RELAY_CHANGE_API', 'api');

// ===========================
// FUNCIONES DE CONFIGURACIÓN
// ===========================

/**
 * Obtener configuración de la base de datos
 */
function get_db_config() {
    return [
        'host' => DB_HOST,
        'dbname' => DB_NAME,
        'username' => DB_USER,
        'password' => DB_PASS,
        'charset' => DB_CHARSET,
        'options' => [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES " . DB_CHARSET
        ]
    ];
}

/**
 * Obtener nivel de permiso de un rol
 */
function get_permission_level($role) {
    global $PERMISSION_LEVELS;
    return $PERMISSION_LEVELS[$role] ?? 0;
}

/**
 * Verificar si un rol tiene un permiso específico
 */
function role_has_permission($role, $permission) {
    global $ROLE_PERMISSIONS;
    
    if (!isset($ROLE_PERMISSIONS[$role])) {
        return false;
    }
    
    // SuperUser tiene todos los permisos
    if (isset($ROLE_PERMISSIONS[$role]['all']) && $ROLE_PERMISSIONS[$role]['all']) {
        return true;
    }
    
    return isset($ROLE_PERMISSIONS[$role][$permission]) && $ROLE_PERMISSIONS[$role][$permission];
}

/**
 * Configurar zona horaria
 */
if (defined('UI_TIMEZONE')) {
    date_default_timezone_set(UI_TIMEZONE);
}

/**
 * Configurar manejo de errores
 */
if (DEBUG_MODE) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
} else {
    error_reporting(E_ERROR | E_WARNING | E_PARSE);
    ini_set('display_errors', 0);
    ini_set('display_startup_errors', 0);
}

/**
 * Configurar límites de PHP
 */
ini_set('max_execution_time', 300); // 5 minutos
ini_set('memory_limit', '256M');
ini_set('post_max_size', '50M');
ini_set('upload_max_filesize', '50M');

/**
 * Headers de seguridad globales
 */
if (!headers_sent()) {
    header('X-Powered-By: SKYN3T/' . SYSTEM_VERSION);
    header('X-Frame-Options: SAMEORIGIN');
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 1; mode=block');
}

/**
 * Autoloader simple para includes
 */
spl_autoload_register(function ($class) {
    $file = INCLUDES_PATH . '/' . strtolower($class) . '.php';
    if (file_exists($file)) {
        require_once $file;
    }
});

/**
 * Crear directorios necesarios si no existen
 */
$required_dirs = [LOG_PATH];
foreach ($required_dirs as $dir) {
    if (!file_exists($dir)) {
        mkdir($dir, 0755, true);
    }
}

/**
 * Función helper para debugging
 */
function debug_log($message, $data = null) {
    if (DEBUG_MODE) {
        $log_message = date('Y-m-d H:i:s') . ' - ' . $message;
        if ($data !== null) {
            $log_message .= ' - ' . print_r($data, true);
        }
        error_log($log_message . PHP_EOL, 3, LOG_PATH . '/debug.log');
    }
}

// Definir constantes adicionales según necesidad
define('CONFIG_LOADED', true);
?>
