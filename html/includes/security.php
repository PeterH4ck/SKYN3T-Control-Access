<?php
/**
 * Archivo: /var/www/html/includes/security.php
 * Funciones de seguridad para el sistema SKYN3T
 */

// Evitar acceso directo
if (!defined('SKYN3T_SYSTEM')) {
    die('Access denied');
}

require_once __DIR__ . '/config.php';

class Security {
    
    /**
     * Generar token seguro
     */
    public static function generateSecureToken($length = 32) {
        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes($length));
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            return bin2hex(openssl_random_pseudo_bytes($length));
        } else {
            // Fallback menos seguro
            return substr(str_shuffle(str_repeat('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/62))), 0, $length);
        }
    }
    
    /**
     * Generar token CSRF
     */
    public static function generateCSRFToken() {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = self::generateSecureToken(CSRF_TOKEN_LENGTH);
        }
        
        return $_SESSION['csrf_token'];
    }
    
    /**
     * Verificar token CSRF
     */
    public static function verifyCSRFToken($token) {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        
        return isset($_SESSION['csrf_token']) && 
               hash_equals($_SESSION['csrf_token'], $token);
    }
    
    /**
     * Limpiar y validar entrada de datos
     */
    public static function sanitizeInput($input, $type = 'string') {
        if (is_array($input)) {
            $sanitized = [];
            foreach ($input as $key => $value) {
                $sanitized[self::sanitizeInput($key, 'string')] = self::sanitizeInput($value, $type);
            }
            return $sanitized;
        }
        
        // Remover caracteres nulos
        $input = str_replace(chr(0), '', $input);
        
        switch ($type) {
            case 'email':
                return filter_var(trim($input), FILTER_SANITIZE_EMAIL);
                
            case 'int':
            case 'integer':
                return filter_var($input, FILTER_SANITIZE_NUMBER_INT);
                
            case 'float':
                return filter_var($input, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
                
            case 'url':
                return filter_var(trim($input), FILTER_SANITIZE_URL);
                
            case 'html':
                return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
                
            case 'sql':
                // Para uso con prepared statements
                return trim($input);
                
            case 'filename':
                // Limpiar nombre de archivo
                $input = preg_replace('/[^a-zA-Z0-9._-]/', '', basename($input));
                return substr($input, 0, 255);
                
            case 'alphanum':
                return preg_replace('/[^a-zA-Z0-9]/', '', $input);
                
            case 'string':
            default:
                return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
        }
    }
    
    /**
     * Validar entrada de datos
     */
    public static function validateInput($input, $rules = []) {
        $errors = [];
        
        foreach ($rules as $field => $fieldRules) {
            $value = $input[$field] ?? null;
            
            foreach ($fieldRules as $rule => $parameter) {
                switch ($rule) {
                    case 'required':
                        if ($parameter && (empty($value) && $value !== '0')) {
                            $errors[$field][] = "El campo $field es requerido";
                        }
                        break;
                        
                    case 'min_length':
                        if (!empty($value) && strlen($value) < $parameter) {
                            $errors[$field][] = "El campo $field debe tener al menos $parameter caracteres";
                        }
                        break;
                        
                    case 'max_length':
                        if (!empty($value) && strlen($value) > $parameter) {
                            $errors[$field][] = "El campo $field no puede tener más de $parameter caracteres";
                        }
                        break;
                        
                    case 'email':
                        if (!empty($value) && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                            $errors[$field][] = "El campo $field debe ser un email válido";
                        }
                        break;
                        
                    case 'numeric':
                        if (!empty($value) && !is_numeric($value)) {
                            $errors[$field][] = "El campo $field debe ser numérico";
                        }
                        break;
                        
                    case 'alpha':
                        if (!empty($value) && !preg_match('/^[a-zA-Z]+$/', $value)) {
                            $errors[$field][] = "El campo $field solo debe contener letras";
                        }
                        break;
                        
                    case 'alphanum':
                        if (!empty($value) && !preg_match('/^[a-zA-Z0-9]+$/', $value)) {
                            $errors[$field][] = "El campo $field solo debe contener letras y números";
                        }
                        break;
                        
                    case 'in':
                        if (!empty($value) && !in_array($value, $parameter)) {
                            $errors[$field][] = "El campo $field debe ser uno de: " . implode(', ', $parameter);
                        }
                        break;
                        
                    case 'regex':
                        if (!empty($value) && !preg_match($parameter, $value)) {
                            $errors[$field][] = "El campo $field no tiene el formato correcto";
                        }
                        break;
                }
            }
        }
        
        return [
            'valid' => empty($errors),
            'errors' => $errors
        ];
    }
    
    /**
     * Validar contraseña
     */
    public static function validatePassword($password) {
        $errors = [];
        
        if (strlen($password) < PASSWORD_MIN_LENGTH) {
            $errors[] = "La contraseña debe tener al menos " . PASSWORD_MIN_LENGTH . " caracteres";
        }
        
        if (PASSWORD_REQUIRE_UPPERCASE && !preg_match('/[A-Z]/', $password)) {
            $errors[] = "La contraseña debe contener al menos una letra mayúscula";
        }
        
        if (PASSWORD_REQUIRE_LOWERCASE && !preg_match('/[a-z]/', $password)) {
            $errors[] = "La contraseña debe contener al menos una letra minúscula";
        }
        
        if (PASSWORD_REQUIRE_NUMBERS && !preg_match('/[0-9]/', $password)) {
            $errors[] = "La contraseña debe contener al menos un número";
        }
        
        if (PASSWORD_REQUIRE_SPECIAL && !preg_match('/[!@#$%^&*(),.?":{}|<>]/', $password)) {
            $errors[] = "La contraseña debe contener al menos un carácter especial";
        }
        
        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'message' => empty($errors) ? 'Contraseña válida' : implode('. ', $errors)
        ];
    }
    
    /**
     * Obtener IP real del cliente
     */
    public static function getClientIP() {
        $ipKeys = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ];
        
        foreach ($ipKeys as $key) {
            if (array_key_exists($key, $_SERVER) && !empty($_SERVER[$key])) {
                $ips = explode(',', $_SERVER[$key]);
                $ip = trim($ips[0]);
                
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
                
                // Si no hay IP pública válida, usar la primera IP
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return 'unknown';
    }
    
    /**
     * Verificar si la IP está en lista blanca
     */
    public static function isIPWhitelisted($ip, $whitelist = []) {
        if (empty($whitelist)) {
            return true; // Si no hay whitelist, permitir todo
        }
        
        foreach ($whitelist as $allowedIP) {
            if (self::ipInRange($ip, $allowedIP)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Verificar si una IP está en un rango
     */
    public static function ipInRange($ip, $range) {
        if (strpos($range, '/') !== false) {
            // CIDR notation
            list($subnet, $mask) = explode('/', $range);
            $subnet = ip2long($subnet);
            $ip = ip2long($ip);
            $mask = -1 << (32 - $mask);
            $subnet &= $mask;
            return ($ip & $mask) == $subnet;
        } else {
            // IP exacta
            return $ip === $range;
        }
    }
    
    /**
     * Hash seguro de datos
     */
    public static function secureHash($data, $salt = '') {
        return hash('sha256', $data . $salt . getConfig('SYSTEM_NAME', 'SKYN3T'));
    }
    
    /**
     * Cifrar datos
     */
    public static function encrypt($data, $key = null) {
        if ($key === null) {
            $key = self::getEncryptionKey();
        }
        
        $method = 'AES-256-CBC';
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method));
        $encrypted = openssl_encrypt($data, $method, $key, 0, $iv);
        
        return base64_encode($iv . $encrypted);
    }
    
    /**
     * Descifrar datos
     */
    public static function decrypt($encryptedData, $key = null) {
        if ($key === null) {
            $key = self::getEncryptionKey();
        }
        
        $method = 'AES-256-CBC';
        $data = base64_decode($encryptedData);
        $ivLength = openssl_cipher_iv_length($method);
        $iv = substr($data, 0, $ivLength);
        $encrypted = substr($data, $ivLength);
        
        return openssl_decrypt($encrypted, $method, $key, 0, $iv);
    }
    
    /**
     * Obtener clave de cifrado
     */
    private static function getEncryptionKey() {
        $key = getConfig('ENCRYPTION_KEY');
        if (!$key) {
            // Generar clave basada en datos del sistema
            $key = hash('sha256', getConfig('SYSTEM_NAME', 'SKYN3T') . getConfig('DB_NAME', 'skyn3t_db'));
        }
        return $key;
    }
    
    /**
     * Verificar fuerza de contraseña
     */
    public static function calculatePasswordStrength($password) {
        $score = 0;
        $feedback = [];
        
        // Longitud
        $length = strlen($password);
        if ($length >= 8) {
            $score += 25;
        } elseif ($length >= 6) {
            $score += 10;
            $feedback[] = "Incrementa la longitud";
        } else {
            $feedback[] = "Contraseña muy corta";
        }
        
        // Letras minúsculas
        if (preg_match('/[a-z]/', $password)) {
            $score += 5;
        } else {
            $feedback[] = "Agrega letras minúsculas";
        }
        
        // Letras mayúsculas
        if (preg_match('/[A-Z]/', $password)) {
            $score += 5;
        } else {
            $feedback[] = "Agrega letras mayúsculas";
        }
        
        // Números
        if (preg_match('/[0-9]/', $password)) {
            $score += 10;
        } else {
            $feedback[] = "Agrega números";
        }
        
        // Caracteres especiales
        if (preg_match('/[!@#$%^&*(),.?":{}|<>]/', $password)) {
            $score += 15;
        } else {
            $feedback[] = "Agrega caracteres especiales";
        }
        
        // Diversidad de caracteres
        $uniqueChars = count(array_unique(str_split($password)));
        if ($uniqueChars > 8) {
            $score += 25;
        } elseif ($uniqueChars > 5) {
            $score += 15;
        }
        
        // Patrones comunes (penalización)
        $commonPatterns = [
            '/(.)\1{2,}/',  // Caracteres repetidos
            '/123|abc|qwe/', // Secuencias comunes
            '/password|admin|user/', // Palabras comunes
        ];
        
        foreach ($commonPatterns as $pattern) {
            if (preg_match($pattern, strtolower($password))) {
                $score -= 20;
                $feedback[] = "Evita patrones comunes";
                break;
            }
        }
        
        $score = max(0, min(100, $score));
        
        if ($score >= 80) {
            $level = 'Muy fuerte';
            $color = '#00ff00';
        } elseif ($score >= 60) {
            $level = 'Fuerte';
            $color = '#90EE90';
        } elseif ($score >= 40) {
            $level = 'Moderada';
            $color = '#FFD700';
        } elseif ($score >= 20) {
            $level = 'Débil';
            $color = '#FFA500';
        } else {
            $level = 'Muy débil';
            $color = '#FF0000';
        }
        
        return [
            'score' => $score,
            'level' => $level,
            'color' => $color,
            'feedback' => $feedback
        ];
    }
    
    /**
     * Limpiar logs antiguos
     */
    public static function cleanOldLogs($maxAge = 2592000) { // 30 días por defecto
        $logFiles = [
            LOG_ERROR_FILE,
            LOG_ACCESS_FILE,
            LOG_SECURITY_FILE,
            LOG_DEBUG_FILE
        ];
        
        foreach ($logFiles as $logFile) {
            if (defined($logFile) && file_exists(constant($logFile))) {
                $file = constant($logFile);
                if (filemtime($file) < (time() - $maxAge)) {
                    // Rotar log
                    self::rotateLog($file);
                }
            }
        }
    }
    
    /**
     * Rotar archivo de log
     */
    private static function rotateLog($logFile) {
        if (!file_exists($logFile)) {
            return;
        }
        
        $maxFiles = getConfig('LOG_MAX_FILES', 5);
        
        // Mover archivos existentes
        for ($i = $maxFiles - 1; $i > 0; $i--) {
            $oldFile = $logFile . '.' . $i;
            $newFile = $logFile . '.' . ($i + 1);
            
            if (file_exists($oldFile)) {
                if ($i == $maxFiles - 1) {
                    unlink($oldFile); // Eliminar el más antiguo
                } else {
                    rename($oldFile, $newFile);
                }
            }
        }
        
        // Mover log actual
        rename($logFile, $logFile . '.1');
        
        // Crear nuevo archivo
        touch($logFile);
        chmod($logFile, 0644);
    }
    
    /**
     * Registrar evento de seguridad
     */
    public static function logSecurityEvent($event, $details = [], $severity = 'INFO') {
        if (!getConfig('ENABLE_SECURITY_LOG', true)) {
            return;
        }
        
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'severity' => $severity,
            'event' => $event,
            'ip' => self::getClientIP(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'details' => $details
        ];
        
        $logLine = json_encode($logEntry) . PHP_EOL;
        
        if (defined('LOG_SECURITY_FILE')) {
            error_log($logLine, 3, LOG_SECURITY_FILE);
        }
        
        // Si es crítico, también al log de errores
        if ($severity === 'CRITICAL' || $severity === 'ERROR') {
            error_log("SECURITY [$severity]: $event - " . json_encode($details));
        }
    }
    
    /**
     * Verificar integridad de archivos críticos
     */
    public static function verifyFileIntegrity($files = []) {
        if (empty($files)) {
            $files = [
                __DIR__ . '/config.php',
                __DIR__ . '/database.php',
                __DIR__ . '/auth.php',
                __DIR__ . '/security.php'
            ];
        }
        
        $results = [];
        
        foreach ($files as $file) {
            if (file_exists($file)) {
                $hash = hash_file('sha256', $file);
                $results[$file] = [
                    'exists' => true,
                    'hash' => $hash,
                    'size' => filesize($file),
                    'modified' => filemtime($file)
                ];
            } else {
                $results[$file] = [
                    'exists' => false
                ];
            }
        }
        
        return $results;
    }
    
    /**
     * Headers de seguridad HTTP
     */
    public static function setSecurityHeaders() {
        // Evitar que se ejecute múltiples veces
        static $headersSet = false;
        if ($headersSet) {
            return;
        }
        
        // Content Security Policy
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';");
        
        // X-Frame-Options
        header('X-Frame-Options: DENY');
        
        // X-Content-Type-Options
        header('X-Content-Type-Options: nosniff');
        
        // X-XSS-Protection
        header('X-XSS-Protection: 1; mode=block');
        
        // Referrer Policy
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // Permissions Policy
        header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
        
        $headersSet = true;
    }
}

// ================================================
// FUNCIONES HELPER GLOBALES
// ================================================

/**
 * Limpiar entrada de datos
 */
function sanitize($input, $type = 'string') {
    return Security::sanitizeInput($input, $type);
}

/**
 * Validar datos de entrada
 */
function validate($input, $rules) {
    return Security::validateInput($input, $rules);
}

/**
 * Generar token CSRF
 */
function csrf_token() {
    return Security::generateCSRFToken();
}

/**
 * Campo oculto con token CSRF
 */
function csrf_field() {
    return '<input type="hidden" name="csrf_token" value="' . csrf_token() . '">';
}

/**
 * Verificar token CSRF
 */
function csrf_verify($token) {
    return Security::verifyCSRFToken($token);
}

/**
 * Obtener IP del cliente
 */
function get_client_ip() {
    return Security::getClientIP();
}

/**
 * Registrar evento de seguridad
 */
function log_security($event, $details = [], $severity = 'INFO') {
    Security::logSecurityEvent($event, $details, $severity);
}

// Establecer headers de seguridad automáticamente
Security::setSecurityHeaders();
?>
