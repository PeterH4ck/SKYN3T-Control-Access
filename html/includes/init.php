<?php
/**
 * SKYN3T - Inicializador Principal del Sistema
 * Archivo: /var/www/html/includes/init.php
 * Punto de entrada único para inicializar todo el sistema
 * 
 * @version 2.0
 * @author SKYN3T Team
 * @database skyn3t_db (MariaDB)
 * 
 * USO: require_once '/var/www/html/includes/init.php';
 */

// Definir constante del sistema
if (!defined('SKYN3T_SYSTEM')) {
    define('SKYN3T_SYSTEM', true);
}

// Definir constantes de rutas
define('SKYN3T_ROOT', '/var/www/html');
define('SKYN3T_INCLUDES', SKYN3T_ROOT . '/includes');
define('SKYN3T_VERSION', '2.0');

// Prevenir múltiples inicializaciones
if (defined('SKYN3T_INITIALIZED')) {
    return;
}

/**
 * Función de auto-carga para manejo de errores
 */
function skyn3tErrorHandler($errno, $errstr, $errfile, $errline) {
    if (!(error_reporting() & $errno)) {
        return false;
    }
    
    $errorTypes = [
        E_ERROR => 'Fatal Error',
        E_WARNING => 'Warning',
        E_PARSE => 'Parse Error',
        E_NOTICE => 'Notice',
        E_CORE_ERROR => 'Core Error',
        E_CORE_WARNING => 'Core Warning',
        E_COMPILE_ERROR => 'Compile Error',
        E_COMPILE_WARNING => 'Compile Warning',
        E_USER_ERROR => 'User Error',
        E_USER_WARNING => 'User Warning',
        E_USER_NOTICE => 'User Notice',
        E_STRICT => 'Strict Notice',
        E_RECOVERABLE_ERROR => 'Recoverable Error',
        E_DEPRECATED => 'Deprecated',
        E_USER_DEPRECATED => 'User Deprecated'
    ];
    
    $errorType = $errorTypes[$errno] ?? 'Unknown Error';
    $logMessage = sprintf(
        "[SKYN3T] %s: %s in %s on line %d",
        $errorType,
        $errstr,
        $errfile,
        $errline
    );
    
    error_log($logMessage);
    
    // En modo debug, mostrar el error
    if (defined('DEBUG') && DEBUG) {
        echo "<div style='color: red; font-family: monospace; padding: 10px; background: #ffe6e6; border: 1px solid #ff0000; margin: 10px;'>";
        echo "<strong>SKYN3T Debug - $errorType:</strong><br>";
        echo "Mensaje: $errstr<br>";
        echo "Archivo: $errfile<br>";
        echo "Línea: $errline<br>";
        echo "</div>";
    }
    
    return true;
}

/**
 * Función para capturar errores fatales
 */
function skyn3tFatalErrorHandler() {
    $error = error_get_last();
    
    if ($error && in_array($error['type'], [E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_RECOVERABLE_ERROR])) {
        $logMessage = sprintf(
            "[SKYN3T] Fatal Error: %s in %s on line %d",
            $error['message'],
            $error['file'],
            $error['line']
        );
        
        error_log($logMessage);
        
        // En modo debug, mostrar el error
        if (defined('DEBUG') && DEBUG) {
            echo "<div style='color: white; background: red; padding: 20px; font-family: monospace;'>";
            echo "<h3>SKYN3T - Error Fatal del Sistema</h3>";
            echo "Mensaje: " . htmlspecialchars($error['message']) . "<br>";
            echo "Archivo: " . htmlspecialchars($error['file']) . "<br>";
            echo "Línea: " . $error['line'] . "<br>";
            echo "</div>";
        } else {
            // En producción, redirigir a página de error
            if (!headers_sent()) {
                header('HTTP/1.1 500 Internal Server Error');
                header('Location: /error.html');
                exit;
            }
        }
    }
}

/**
 * Verificar requisitos del sistema
 */
function checkSystemRequirements() {
    $errors = [];
    
    // Verificar versión de PHP
    if (version_compare(PHP_VERSION, '7.4.0', '<')) {
        $errors[] = 'Se requiere PHP 7.4.0 o superior. Versión actual: ' . PHP_VERSION;
    }
    
    // Verificar extensiones requeridas
    $requiredExtensions = ['pdo', 'pdo_mysql', 'json', 'openssl', 'hash'];
    foreach ($requiredExtensions as $extension) {
        if (!extension_loaded($extension)) {
            $errors[] = "Extensión PHP requerida no encontrada: $extension";
        }
    }
    
    // Verificar permisos de escritura
    $writableDirs = [
        SKYN3T_ROOT . '/logs',
        SKYN3T_ROOT . '/cache',
        SKYN3T_ROOT . '/uploads'
    ];
    
    foreach ($writableDirs as $dir) {
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        
        if (!is_writable($dir)) {
            $errors[] = "Directorio sin permisos de escritura: $dir";
        }
    }
    
    return $errors;
}

/**
 * Inicializar el sistema
 */
function initializeSystem() {
    try {
        // Configurar manejadores de errores
        set_error_handler('skyn3tErrorHandler');
        register_shutdown_function('skyn3tFatalErrorHandler');
        
        // Verificar requisitos
        $systemErrors = checkSystemRequirements();
        if (!empty($systemErrors)) {
            foreach ($systemErrors as $error) {
                error_log("[SKYN3T] System Requirement Error: $error");
            }
            
            if (defined('DEBUG') && DEBUG) {
                echo "<div style='color: red; background: #ffe6e6; padding: 20px; border: 2px solid red; margin: 20px;'>";
                echo "<h3>SKYN3T - Errores de Requisitos del Sistema</h3>";
                echo "<ul>";
                foreach ($systemErrors as $error) {
                    echo "<li>" . htmlspecialchars($error) . "</li>";
                }
                echo "</ul>";
                echo "</div>";
            }
        }
        
        // Incluir archivos principales en orden
        $includeFiles = [
            'config.php',
            'database.php',
            'functions.php',
            'auth.php'
        ];
        
        foreach ($includeFiles as $file) {
            $filePath = SKYN3T_INCLUDES . '/' . $file;
            
            if (!file_exists($filePath)) {
                throw new Exception("Archivo requerido no encontrado: $filePath");
            }
            
            require_once $filePath;
        }
        
        // Configurar configuraciones PHP
        configurePhpSettings();
        
        // Verificar conexión a la base de datos
        $db = Database::getInstance();
        if (!$db->isConnected()) {
            throw new Exception("No se puede conectar a la base de datos skyn3t_db");
        }
        
        // Log de inicialización exitosa
        error_log("[SKYN3T] Sistema inicializado correctamente - Versión " . SKYN3T_VERSION);
        
        return true;
        
    } catch (Exception $e) {
        $errorMsg = "[SKYN3T] Error crítico en inicialización: " . $e->getMessage();
        error_log($errorMsg);
        
        if (defined('DEBUG') && DEBUG) {
            echo "<div style='color: white; background: red; padding: 20px; font-weight: bold;'>";
            echo "SKYN3T - Error Crítico de Inicialización<br>";
            echo htmlspecialchars($e->getMessage());
            echo "</div>";
        }
        
        return false;
    }
}

/**
 * Función para verificar estado del sistema después de la inicialización
 */
function verifySystemHealth() {
    if (!defined('SKYN3T_INITIALIZED')) {
        return false;
    }
    
    try {
        // Verificar base de datos
        $db = Database::getInstance();
        if (!$db->isConnected()) {
            return false;
        }
        
        // Verificar estructura de la base de datos
        $structure = $db->checkDatabaseStructure();
        if ($structure['connection'] !== 'OK') {
            return false;
        }
        
        // Verificar permisos de archivos críticos
        $criticalFiles = [
            SKYN3T_INCLUDES . '/database.php',
            SKYN3T_INCLUDES . '/auth.php',
            SKYN3T_INCLUDES . '/config.php'
        ];
        
        foreach ($criticalFiles as $file) {
            if (!file_exists($file) || !is_readable($file)) {
                return false;
            }
        }
        
        return true;
        
    } catch (Exception $e) {
        error_log("[SKYN3T] Error en verificación de salud del sistema: " . $e->getMessage());
        return false;
    }
}

/**
 * Función auxiliar para obtener información de debug
 */
function getSystemDebugInfo() {
    return [
        'system' => [
            'version' => SKYN3T_VERSION,
            'php_version' => PHP_VERSION,
            'initialized' => defined('SKYN3T_INITIALIZED'),
            'debug_mode' => defined('DEBUG') && DEBUG,
            'maintenance_mode' => defined('MAINTENANCE') && MAINTENANCE
        ],
        'paths' => [
            'root' => SKYN3T_ROOT,
            'includes' => SKYN3T_INCLUDES,
            'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? 'unknown'
        ],
        'database' => [
            'connected' => class_exists('Database') ? Database::getInstance()->isConnected() : false,
            'name' => defined('DatabaseConfig::DB_NAME') ? DatabaseConfig::DB_NAME : 'unknown'
        ],
        'session' => [
            'status' => session_status(),
            'id' => session_id(),
            'active' => session_status() === PHP_SESSION_ACTIVE
        ],
        'server' => [
            'software' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
            'uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
            'time' => date('Y-m-d H:i:s')
        ]
    ];
}

// === INICIALIZACIÓN AUTOMÁTICA ===

// Inicializar el sistema
if (initializeSystem()) {
    // Marcar como inicializado
    define('SKYN3T_INITIALIZED', true);
    
    // En modo debug, mostrar información del sistema
    if (defined('DEBUG') && DEBUG && isset($_GET['debug']) && $_GET['debug'] === 'info') {
        header('Content-Type: application/json');
        echo json_encode(getSystemDebugInfo(), JSON_PRETTY_PRINT);
        exit;
    }
} else {
    // Error crítico - no se pudo inicializar
    if (!headers_sent()) {
        header('HTTP/1.1 500 Internal Server Error');
        header('Content-Type: text/plain');
        echo "SKYN3T System: Error crítico de inicialización. Consulte los logs del servidor.";
        exit;
    }
}

// Definir función global para acceso rápido a la información del sistema
if (!function_exists('skyn3t_info')) {
    function skyn3t_info() {
        return [
            'name' => 'SKYN3T',
            'version' => SKYN3T_VERSION,
            'initialized' => defined('SKYN3T_INITIALIZED'),
            'healthy' => verifySystemHealth(),
            'timestamp' => date('c')
        ];
    }
}

?>