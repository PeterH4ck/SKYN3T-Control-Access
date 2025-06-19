<?php
/**
 * Archivo: /var/www/html/includes/config.php
 * Configuraciones generales del sistema SKYN3T
 */

// Evitar acceso directo
if (!defined('SKYN3T_SYSTEM')) {
    define('SKYN3T_SYSTEM', true);
}

// ================================================
// CONFIGURACIÓN GENERAL DEL SISTEMA
// ================================================

// Información del sistema
define('SYSTEM_NAME', 'SKYN3T');
define('SYSTEM_VERSION', '2.0.0');
define('SYSTEM_DESCRIPTION', 'Sistema de Control y Monitoreo');
define('SYSTEM_COPYRIGHT', '© 2025 SKYN3T Systems');

// Configuración del servidor
define('SERVER_IP', '192.168.4.1');
define('SERVER_PORT', '80');
define('BASE_URL', 'http://' . SERVER_IP . ':' . SERVER_PORT);
define('DOCUMENT_ROOT', '/var/www/html');

// ================================================
// CONFIGURACIÓN DE BASE DE DATOS
// ================================================

// Configuración principal
define('DB_HOST', 'localhost');
define('DB_NAME', 'skyn3t_db');
define('DB_USER', 'admin');
define('DB_PASS', 'admin');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATION', 'utf8mb4_unicode_ci');

// Configuración alternativa (más segura)
define('DB_APP_USER', 'skyn3t_app');
define('DB_APP_PASS', 'Skyn3t2025!');

// ================================================
// CONFIGURACIÓN DE SESIONES
// ================================================

// Duración de sesiones
define('SESSION_LIFETIME', 3600); // 1 hora
define('SESSION_REMEMBER_LIFETIME', 86400 * 7); // 7 días
define('SESSION_CLEANUP_PROBABILITY', 1); // 1% de probabilidad de limpieza automática

// Configuración de cookies de sesión
define('SESSION_COOKIE_NAME', 'SKYN3T_SESSION');
define('SESSION_COOKIE_LIFETIME', 0); // Hasta cerrar navegador
define('SESSION_COOKIE_PATH', '/');
define('SESSION_COOKIE_DOMAIN', '');
define('SESSION_COOKIE_SECURE', false); // Cambiar a true en HTTPS
define('SESSION_COOKIE_HTTPONLY', true);

// ================================================
// CONFIGURACIÓN DE SEGURIDAD
// ================================================

// Intentos de login
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_TIME', 900); // 15 minutos en segundos

// Configuración de tokens
define('TOKEN_LENGTH', 32);
define('CSRF_TOKEN_LENGTH', 32);

// Rate limiting
define('RATE_LIMIT_REQUESTS', 100); // Requests por minuto
define('RATE_LIMIT_WINDOW', 60); // Ventana en segundos

// Configuración de contraseñas
define('PASSWORD_MIN_LENGTH', 6);
define('PASSWORD_REQUIRE_UPPERCASE', false);
define('PASSWORD_REQUIRE_LOWERCASE', false);
define('PASSWORD_REQUIRE_NUMBERS', false);
define('PASSWORD_REQUIRE_SPECIAL', false);

// ================================================
// CONFIGURACIÓN DE ARCHIVOS Y DIRECTORIOS
// ================================================

// Directorios del sistema
define('DIR_INCLUDES', DOCUMENT_ROOT . '/includes');
define('DIR_LOGIN', DOCUMENT_ROOT . '/login');
define('DIR_API', DOCUMENT_ROOT . '/api');
define('DIR_DASHBOARD', DOCUMENT_ROOT . '/dashboard');
define('DIR_DEVICES', DOCUMENT_ROOT . '/devices');
define('DIR_RELE', DOCUMENT_ROOT . '/rele');
define('DIR_IMAGES', DOCUMENT_ROOT . '/images');
define('DIR_ASSETS', DOCUMENT_ROOT . '/assets');
define('DIR_LOGS', DOCUMENT_ROOT . '/logs');

// URLs del sistema
define('URL_LOGIN', BASE_URL . '/login/index_login.html');
define('URL_DASHBOARD', BASE_URL . '/dashboard/index.php');
define('URL_API', BASE_URL . '/api');
define('URL_RELE', BASE_URL . '/rele/index_rele.html');
define('URL_DEVICES', BASE_URL . '/devices/index_devices.html');

// ================================================
// CONFIGURACIÓN DE LOGS
// ================================================

// Activar/desactivar logs
define('ENABLE_ERROR_LOG', true);
define('ENABLE_ACCESS_LOG', true);
define('ENABLE_SECURITY_LOG', true);
define('ENABLE_DEBUG_LOG', false);

// Archivos de log
define('LOG_ERROR_FILE', DIR_LOGS . '/error.log');
define('LOG_ACCESS_FILE', DIR_LOGS . '/access.log');
define('LOG_SECURITY_FILE', DIR_LOGS . '/security.log');
define('LOG_DEBUG_FILE', DIR_LOGS . '/debug.log');

// Rotación de logs
define('LOG_MAX_SIZE', 10485760); // 10MB
define('LOG_MAX_FILES', 5);

// ================================================
// CONFIGURACIÓN DEL RELÉ
// ================================================

// GPIO Configuration
define('RELAY_GPIO_PIN', 23);
define('LED_GPIO_PIN', 16);
define('BUTTON_GPIO_PIN', 25);

// Control settings
define('RELAY_DEFAULT_STATE', 0); // OFF por defecto
define('LED_DEFAULT_STATE', 0); // OFF por defecto

// API endpoints
define('RELAY_CONTROL_ENDPOINT', URL_API . '/relay/control.php');
define('RELAY_STATUS_ENDPOINT', URL_API . '/relay/status.php');

// ================================================
// CONFIGURACIÓN DE ROLES Y PERMISOS
// ================================================

// Definición de roles
define('ROLE_SUPER_USER', 'SuperUser');
define('ROLE_ADMIN', 'Admin');
define('ROLE_SUPPORT_ADMIN', 'SupportAdmin');
define('ROLE_USER', 'User');

// Jerarquía de roles (mayor número = más permisos)
$GLOBALS['ROLE_HIERARCHY'] = [
    ROLE_USER => 1,
    ROLE_SUPPORT_ADMIN => 2,
    ROLE_ADMIN => 3,
    ROLE_SUPER_USER => 4
];

// Permisos por defecto
$GLOBALS['DEFAULT_PERMISSIONS'] = [
    ROLE_USER => [
        'input_data' => true,
        'view_own_data' => true
    ],
    ROLE_SUPPORT_ADMIN => [
        'input_data' => true,
        'view_own_data' => true,
        'view_logs' => true,
        'view_devices' => true
    ],
    ROLE_ADMIN => [
        'input_data' => true,
        'view_own_data' => true,
        'view_logs' => true,
        'view_devices' => true,
        'manage_devices' => true,
        'control_relay' => true,
        'dashboard' => true,
        'manage_users' => true
    ],
    ROLE_SUPER_USER => [
        'all' => true,
        'system_admin' => true,
        'database_admin' => true,
        'security_admin' => true
    ]
];

// ================================================
// CONFIGURACIÓN DE ENTORNO
// ================================================

// Detectar entorno
if (!defined('ENVIRONMENT')) {
    if (isset($_SERVER['SKYN3T_ENV'])) {
        define('ENVIRONMENT', $_SERVER['SKYN3T_ENV']);
    } elseif (file_exists(DOCUMENT_ROOT . '/.env.production')) {
        define('ENVIRONMENT', 'production');
    } elseif (file_exists(DOCUMENT_ROOT . '/.env.development')) {
        define('ENVIRONMENT', 'development');
    } else {
        define('ENVIRONMENT', 'development');
    }
}

// Configuración por entorno
switch (ENVIRONMENT) {
    case 'production':
        define('DEBUG_MODE', false);
        define('DISPLAY_ERRORS', false);
        define('ERROR_REPORTING_LEVEL', E_ERROR | E_WARNING);
        break;
        
    case 'development':
    default:
        define('DEBUG_MODE', true);
        define('DISPLAY_ERRORS', true);
        define('ERROR_REPORTING_LEVEL', E_ALL);
        break;
}

// ================================================
// CONFIGURACIÓN DE PHP
// ================================================

// Configurar PHP según el entorno
if (DISPLAY_ERRORS) {
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
} else {
    ini_set('display_errors', 0);
    ini_set('display_startup_errors', 0);
}

error_reporting(ERROR_REPORTING_LEVEL);

// Configuración de zona horaria
date_default_timezone_set('America/Santiago');

// Configuración de memoria y tiempo
ini_set('memory_limit', '256M');
ini_set('max_execution_time', 30);

// ================================================
// FUNCIONES HELPER DE CONFIGURACIÓN
// ================================================

/**
 * Obtener valor de configuración
 */
function getConfig($key, $default = null) {
    return defined($key) ? constant($key) : $default;
}

/**
 * Verificar si está en modo debug
 */
function isDebugMode() {
    return getConfig('DEBUG_MODE', false);
}

/**
 * Obtener URL base del sistema
 */
function getBaseUrl() {
    return getConfig('BASE_URL', 'http://192.168.4.1');
}

/**
 * Obtener información del sistema
 */
function getSystemInfo() {
    return [
        'name' => getConfig('SYSTEM_NAME'),
        'version' => getConfig('SYSTEM_VERSION'),
        'description' => getConfig('SYSTEM_DESCRIPTION'),
        'copyright' => getConfig('SYSTEM_COPYRIGHT'),
        'environment' => getConfig('ENVIRONMENT'),
        'debug_mode' => isDebugMode(),
        'base_url' => getBaseUrl(),
        'server_ip' => getConfig('SERVER_IP'),
        'timestamp' => date('Y-m-d H:i:s')
    ];
}

/**
 * Verificar si un rol tiene permisos específicos
 */
function hasPermission($userRole, $permission) {
    global $DEFAULT_PERMISSIONS;
    
    // SuperUser tiene todos los permisos
    if ($userRole === ROLE_SUPER_USER) {
        return true;
    }
    
    // Verificar permisos específicos del rol
    if (isset($DEFAULT_PERMISSIONS[$userRole])) {
        $rolePermissions = $DEFAULT_PERMISSIONS[$userRole];
        
        // Si tiene permiso 'all', puede hacer todo
        if (isset($rolePermissions['all']) && $rolePermissions['all']) {
            return true;
        }
        
        // Verificar permiso específico
        return isset($rolePermissions[$permission]) && $rolePermissions[$permission];
    }
    
    return false;
}

/**
 * Obtener jerarquía de rol
 */
function getRoleLevel($role) {
    global $ROLE_HIERARCHY;
    return $ROLE_HIERARCHY[$role] ?? 0;
}

/**
 * Verificar si un rol es superior a otro
 */
function isRoleHigherThan($role1, $role2) {
    return getRoleLevel($role1) > getRoleLevel($role2);
}

// ================================================
// INICIALIZACIÓN AUTOMÁTICA
// ================================================

// Crear directorios necesarios si no existen
$requiredDirs = [
    DIR_LOGS,
    DIR_ASSETS . '/css',
    DIR_ASSETS . '/js'
];

foreach ($requiredDirs as $dir) {
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
}

// Configurar manejo de errores personalizado
if (ENABLE_ERROR_LOG) {
    set_error_handler('customErrorHandler');
    set_exception_handler('customExceptionHandler');
}

/**
 * Manejador personalizado de errores
 */
function customErrorHandler($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    
    $errorMsg = sprintf(
        "[%s] Error: %s in %s on line %d",
        date('Y-m-d H:i:s'),
        $message,
        $file,
        $line
    );
    
    if (ENABLE_ERROR_LOG && defined('LOG_ERROR_FILE')) {
        error_log($errorMsg . PHP_EOL, 3, LOG_ERROR_FILE);
    }
    
    if (isDebugMode()) {
        echo "<div style='color: red; background: #fee; padding: 10px; margin: 5px; border: 1px solid #fcc;'>";
        echo "<strong>Error:</strong> $message<br>";
        echo "<strong>File:</strong> $file<br>";
        echo "<strong>Line:</strong> $line";
        echo "</div>";
    }
    
    return true;
}

/**
 * Manejador personalizado de excepciones
 */
function customExceptionHandler($exception) {
    $errorMsg = sprintf(
        "[%s] Uncaught Exception: %s in %s on line %d",
        date('Y-m-d H:i:s'),
        $exception->getMessage(),
        $exception->getFile(),
        $exception->getLine()
    );
    
    if (ENABLE_ERROR_LOG && defined('LOG_ERROR_FILE')) {
        error_log($errorMsg . PHP_EOL, 3, LOG_ERROR_FILE);
    }
    
    if (isDebugMode()) {
        echo "<div style='color: red; background: #fee; padding: 10px; margin: 5px; border: 1px solid #fcc;'>";
        echo "<strong>Uncaught Exception:</strong> " . $exception->getMessage() . "<br>";
        echo "<strong>File:</strong> " . $exception->getFile() . "<br>";
        echo "<strong>Line:</strong> " . $exception->getLine();
        echo "</div>";
    } else {
        echo "System error occurred. Please try again later.";
    }
}
?>
