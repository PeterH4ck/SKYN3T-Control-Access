<?php
/**
 * SKYN3T - Funciones Auxiliares del Sistema
 * Archivo: /var/www/html/includes/functions.php
 * Funciones útiles para todo el sistema
 * 
 * @version 2.0
 * @author SKYN3T Team
 * @database skyn3t_db (MariaDB)
 */

// Prevenir acceso directo
if (!defined('SKYN3T_SYSTEM')) {
    define('SKYN3T_SYSTEM', true);
}

// Incluir dependencias
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';

/**
 * Funciones de seguridad
 */

/**
 * Sanitizar entrada de usuario
 * 
 * @param mixed $input
 * @param string $type
 * @return mixed
 */
function sanitizeInput($input, $type = 'string') {
    if (is_array($input)) {
        return array_map(function($item) use ($type) {
            return sanitizeInput($item, $type);
        }, $input);
    }
    
    switch ($type) {
        case 'email':
            return filter_var($input, FILTER_SANITIZE_EMAIL);
        case 'url':
            return filter_var($input, FILTER_SANITIZE_URL);
        case 'int':
            return filter_var($input, FILTER_SANITIZE_NUMBER_INT);
        case 'float':
            return filter_var($input, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
        case 'string':
        default:
            return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
    }
}

/**
 * Validar entrada de usuario
 * 
 * @param mixed $input
 * @param string $type
 * @param array $options
 * @return bool
 */
function validateInput($input, $type, $options = []) {
    switch ($type) {
        case 'email':
            return filter_var($input, FILTER_VALIDATE_EMAIL) !== false;
        case 'url':
            return filter_var($input, FILTER_VALIDATE_URL) !== false;
        case 'int':
            $min = $options['min'] ?? null;
            $max = $options['max'] ?? null;
            $flags = [];
            if ($min !== null) $flags['min_range'] = $min;
            if ($max !== null) $flags['max_range'] = $max;
            return filter_var($input, FILTER_VALIDATE_INT, ['options' => $flags]) !== false;
        case 'float':
            return filter_var($input, FILTER_VALIDATE_FLOAT) !== false;
        case 'username':
            return preg_match('/^[a-zA-Z0-9_]{3,20}$/', $input);
        case 'password':
            $minLength = $options['min_length'] ?? 6;
            return strlen($input) >= $minLength;
        case 'required':
            return !empty(trim($input));
        case 'length':
            $min = $options['min'] ?? 0;
            $max = $options['max'] ?? PHP_INT_MAX;
            $length = strlen($input);
            return $length >= $min && $length <= $max;
        default:
            return true;
    }
}

/**
 * Generar token CSRF
 * 
 * @return string
 */
function generateCSRFToken() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    $token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $token;
    $_SESSION['csrf_time'] = time();
    
    return $token;
}

/**
 * Verificar token CSRF
 * 
 * @param string $token
 * @return bool
 */
function verifyCSRFToken($token) {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['csrf_time'])) {
        return false;
    }
    
    // Verificar expiración (30 minutos)
    if (time() - $_SESSION['csrf_time'] > 1800) {
        unset($_SESSION['csrf_token'], $_SESSION['csrf_time']);
        return false;
    }
    
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Generar hash de contraseña seguro
 * 
 * @param string $password
 * @return string
 */
function hashPassword($password) {
    return password_hash($password, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost' => 4,
        'threads' => 3
    ]);
}

/**
 * Funciones de respuesta HTTP
 */

/**
 * Enviar respuesta JSON
 * 
 * @param array $data
 * @param int $httpCode
 */
function sendJSONResponse($data, $httpCode = 200) {
    http_response_code($httpCode);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-cache, must-revalidate');
    header('Expires: Sat, 26 Jul 1997 05:00:00 GMT');
    
    // Agregar headers de seguridad
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

/**
 * Enviar respuesta de error
 * 
 * @param string $message
 * @param int $httpCode
 * @param string $errorCode
 */
function sendErrorResponse($message, $httpCode = 400, $errorCode = null) {
    $response = [
        'success' => false,
        'error' => true,
        'message' => $message,
        'timestamp' => date('c')
    ];
    
    if ($errorCode) {
        $response['error_code'] = $errorCode;
    }
    
    if (isDebugMode()) {
        $response['debug'] = [
            'file' => debug_backtrace()[0]['file'] ?? 'unknown',
            'line' => debug_backtrace()[0]['line'] ?? 'unknown'
        ];
    }
    
    sendJSONResponse($response, $httpCode);
}

/**
 * Enviar respuesta de éxito
 * 
 * @param mixed $data
 * @param string $message
 */
function sendSuccessResponse($data = null, $message = 'Operación exitosa') {
    $response = [
        'success' => true,
        'error' => false,
        'message' => $message,
        'timestamp' => date('c')
    ];
    
    if ($data !== null) {
        $response['data'] = $data;
    }
    
    sendJSONResponse($response, 200);
}

/**
 * Funciones de logging
 */

/**
 * Escribir log del sistema
 * 
 * @param string $level
 * @param string $message
 * @param array $context
 */
function writeLog($level, $message, $context = []) {
    $logLevels = SystemConfig::LOG_LEVELS;
    
    if (!isset($logLevels[$level])) {
        $level = 'info';
    }
    
    $timestamp = date('Y-m-d H:i:s');
    $contextStr = !empty($context) ? ' | Context: ' . json_encode($context) : '';
    $userInfo = getCurrentUser();
    $userStr = $userInfo ? ' | User: ' . $userInfo['username'] : ' | User: anonymous';
    
    $logMessage = sprintf(
        "[%s] [%s] %s%s%s\n",
        $timestamp,
        strtoupper($level),
        $message,
        $userStr,
        $contextStr
    );
    
    // Log en archivo del sistema
    error_log($logMessage, 3, SystemConfig::BASE_PATH . '/logs/system.log');
    
    // Log en base de datos si es crítico
    if (in_array($level, ['emergency', 'alert', 'critical', 'error'])) {
        logToDatabase($level, $message, $context);
    }
}

/**
 * Log en base de datos
 * 
 * @param string $level
 * @param string $message
 * @param array $context
 */
function logToDatabase($level, $message, $context = []) {
    try {
        $db = Database::getInstance();
        $user = getCurrentUser();
        
        $sql = "
            INSERT INTO system_logs (level, message, context, user_id, username, ip_address, user_agent, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
        ";
        
        $db->prepare($sql, [
            $level,
            $message,
            json_encode($context),
            $user['id'] ?? null,
            $user['username'] ?? 'anonymous',
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ]);
        
    } catch (Exception $e) {
        error_log("Error logging to database: " . $e->getMessage());
    }
}

/**
 * Funciones de formato y utilidades
 */

/**
 * Formatear fecha
 * 
 * @param string $date
 * @param string $format
 * @return string
 */
function formatDate($date, $format = null) {
    if (!$format) {
        $format = SystemConfig::DATE_DISPLAY_FORMAT;
    }
    
    if (is_string($date)) {
        $date = new DateTime($date);
    }
    
    return $date->format($format);
}

/**
 * Formatear bytes
 * 
 * @param int $bytes
 * @param int $precision
 * @return string
 */
function formatBytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    
    for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
        $bytes /= 1024;
    }
    
    return round($bytes, $precision) . ' ' . $units[$i];
}

/**
 * Generar ID único
 * 
 * @param string $prefix
 * @return string
 */
function generateUniqueId($prefix = '') {
    return $prefix . uniqid() . bin2hex(random_bytes(4));
}

/**
 * Verificar si es una petición AJAX
 * 
 * @return bool
 */
function isAjaxRequest() {
    return isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
           strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

/**
 * Obtener IP del cliente
 * 
 * @return string
 */
function getClientIP() {
    $ipKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    
    foreach ($ipKeys as $key) {
        if (isset($_SERVER[$key]) && !empty($_SERVER[$key])) {
            $ips = explode(',', $_SERVER[$key]);
            $ip = trim($ips[0]);
            
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/**
 * Funciones de notificaciones
 */

/**
 * Crear notificación del sistema
 * 
 * @param string $type
 * @param string $title
 * @param string $message
 * @param int $userId
 * @return bool
 */
function createNotification($type, $title, $message, $userId = null) {
    try {
        $db = Database::getInstance();
        $user = getCurrentUser();
        
        if (!$userId && $user) {
            $userId = $user['id'];
        }
        
        $sql = "
            INSERT INTO notifications (user_id, type, title, message, is_read, created_at)
            VALUES (?, ?, ?, ?, 0, NOW())
        ";
        
        return $db->prepare($sql, [$userId, $type, $title, $message]) !== false;
        
    } catch (Exception $e) {
        writeLog('error', 'Error creating notification: ' . $e->getMessage());
        return false;
    }
}

/**
 * Funciones de cache simple
 */

/**
 * Obtener del cache
 * 
 * @param string $key
 * @return mixed|null
 */
function getCache($key) {
    $cacheFile = SystemConfig::BASE_PATH . '/cache/' . md5($key) . '.cache';
    
    if (file_exists($cacheFile)) {
        $cache = unserialize(file_get_contents($cacheFile));
        
        if ($cache['expires'] > time()) {
            return $cache['data'];
        } else {
            unlink($cacheFile);
        }
    }
    
    return null;
}

/**
 * Guardar en cache
 * 
 * @param string $key
 * @param mixed $data
 * @param int $ttl
 * @return bool
 */
function setCache($key, $data, $ttl = 3600) {
    $cacheDir = SystemConfig::BASE_PATH . '/cache';
    
    if (!is_dir($cacheDir)) {
        mkdir($cacheDir, 0755, true);
    }
    
    $cacheFile = $cacheDir . '/' . md5($key) . '.cache';
    
    $cache = [
        'data' => $data,
        'expires' => time() + $ttl
    ];
    
    return file_put_contents($cacheFile, serialize($cache)) !== false;
}

/**
 * Limpiar cache
 * 
 * @param string $key
 * @return bool
 */
function clearCache($key = null) {
    $cacheDir = SystemConfig::BASE_PATH . '/cache';
    
    if (!is_dir($cacheDir)) {
        return true;
    }
    
    if ($key) {
        $cacheFile = $cacheDir . '/' . md5($key) . '.cache';
        return file_exists($cacheFile) ? unlink($cacheFile) : true;
    } else {
        // Limpiar todo el cache
        $files = glob($cacheDir . '/*.cache');
        foreach ($files as $file) {
            unlink($file);
        }
        return true;
    }
}

/**
 * Funciones de validación de archivos
 */

/**
 * Validar archivo subido
 * 
 * @param array $file
 * @return array
 */
function validateUploadedFile($file) {
    $errors = [];
    
    // Verificar si hay errores de upload
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errors[] = 'Error al subir el archivo';
        return ['valid' => false, 'errors' => $errors];
    }
    
    // Verificar tamaño
    if ($file['size'] > SystemConfig::MAX_UPLOAD_SIZE) {
        $errors[] = 'Archivo demasiado grande. Máximo: ' . formatBytes(SystemConfig::MAX_UPLOAD_SIZE);
    }
    
    // Verificar tipo de archivo
    $fileExtension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($fileExtension, SystemConfig::ALLOWED_FILE_TYPES)) {
        $errors[] = 'Tipo de archivo no permitido. Permitidos: ' . implode(', ', SystemConfig::ALLOWED_FILE_TYPES);
    }
    
    // Verificar que es un archivo real
    if (!is_uploaded_file($file['tmp_name'])) {
        $errors[] = 'Archivo inválido';
    }
    
    return [
        'valid' => empty($errors),
        'errors' => $errors,
        'extension' => $fileExtension,
        'size' => $file['size'],
        'mime_type' => mime_content_type($file['tmp_name'])
    ];
}

/**
 * Funciones de sistema
 */

/**
 * Verificar estado del sistema
 * 
 * @return array
 */
function getSystemStatus() {
    $db = Database::getInstance();
    
    return [
        'system' => [
            'name' => SystemConfig::SYSTEM_NAME,
            'version' => SystemConfig::SYSTEM_VERSION,
            'status' => 'running',
            'uptime' => getSystemUptime(),
            'maintenance_mode' => isMaintenanceMode()
        ],
        'database' => [
            'connected' => $db->isConnected(),
            'name' => DatabaseConfig::DB_NAME,
            'host' => DatabaseConfig::DB_HOST
        ],
        'memory' => [
            'used' => formatBytes(memory_get_usage(true)),
            'peak' => formatBytes(memory_get_peak_usage(true)),
            'limit' => ini_get('memory_limit')
        ],
        'disk' => [
            'free' => formatBytes(disk_free_space('.')),
            'total' => formatBytes(disk_total_space('.'))
        ]
    ];
}

/**
 * Obtener tiempo de actividad del sistema
 * 
 * @return string
 */
function getSystemUptime() {
    if (function_exists('sys_getloadavg')) {
        $uptime = shell_exec('uptime');
        return trim($uptime) ?: 'No disponible';
    }
    
    return 'No disponible';
}

// Auto-crear directorios necesarios
if (!defined('SKYN3T_NO_AUTO_SETUP')) {
    $directories = [
        SystemConfig::BASE_PATH . '/logs',
        SystemConfig::BASE_PATH . '/cache',
        SystemConfig::BASE_PATH . '/uploads'
    ];
    
    foreach ($directories as $dir) {
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
    }
}

?>