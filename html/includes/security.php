<?php
/**
 * SKYN3T - Sistema de Control y Monitoreo
 * Funciones de seguridad centralizadas
 * 
 * @version 2.0.0
 * @date 2025-01-19
 */

// Incluir configuración
require_once __DIR__ . '/config.php';

// ===========================
// SANITIZACIÓN Y VALIDACIÓN
// ===========================

/**
 * Sanitizar input de usuario
 */
function sanitize_input($input) {
    if (is_array($input)) {
        return array_map('sanitize_input', $input);
    }
    
    $input = trim($input);
    $input = stripslashes($input);
    $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    
    return $input;
}

/**
 * Validar email
 */
function validate_email($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validar IP
 */
function validate_ip($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

/**
 * Validar formato MAC address
 */
function validate_mac_address($mac) {
    return preg_match('/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/', $mac);
}

// ===========================
// CONTRASEÑAS
// ===========================

/**
 * Validar fortaleza de contraseña
 */
function validate_password_strength($password) {
    $errors = [];
    
    if (strlen($password) < PASSWORD_MIN_LENGTH) {
        $errors[] = 'La contraseña debe tener al menos ' . PASSWORD_MIN_LENGTH . ' caracteres';
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = 'La contraseña debe contener al menos una letra mayúscula';
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = 'La contraseña debe contener al menos una letra minúscula';
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = 'La contraseña debe contener al menos un número';
    }
    
    if (!preg_match('/[!@#$%^&*(),.?":{}|<>]/', $password)) {
        $errors[] = 'La contraseña debe contener al menos un carácter especial';
    }
    
    return [
        'valid' => empty($errors),
        'errors' => $errors,
        'strength' => calculate_password_strength($password)
    ];
}

/**
 * Calcular fortaleza de contraseña
 */
function calculate_password_strength($password) {
    $strength = 0;
    
    if (strlen($password) >= 8) $strength += 20;
    if (strlen($password) >= 12) $strength += 20;
    if (preg_match('/[a-z]/', $password)) $strength += 15;
    if (preg_match('/[A-Z]/', $password)) $strength += 15;
    if (preg_match('/[0-9]/', $password)) $strength += 15;
    if (preg_match('/[^a-zA-Z0-9]/', $password)) $strength += 15;
    
    if ($strength >= 80) return 'strong';
    if ($strength >= 60) return 'medium';
    return 'weak';
}

/**
 * Generar contraseña aleatoria segura
 */
function generate_random_password($length = 12) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()';
    $password = '';
    
    for ($i = 0; $i < $length; $i++) {
        $password .= $chars[random_int(0, strlen($chars) - 1)];
    }
    
    return $password;
}

// ===========================
// TOKENS Y CSRF
// ===========================

/**
 * Generar token seguro
 */
function generate_secure_token($length = 32) {
    return bin2hex(random_bytes($length / 2));
}

/**
 * Generar token CSRF
 */
function generate_csrf_token() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = generate_secure_token(CSRF_TOKEN_LENGTH);
    }
    
    return $_SESSION['csrf_token'];
}

/**
 * Validar token CSRF
 */
function validate_csrf_token($token) {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    if (!isset($_SESSION['csrf_token'])) {
        return false;
    }
    
    return hash_equals($_SESSION['csrf_token'], $token);
}

// ===========================
// HEADERS Y CORS
// ===========================

/**
 * Headers de seguridad HTTP
 */
function set_security_headers() {
    if (headers_sent()) {
        return;
    }
    
    // Prevenir ataques XSS
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('X-XSS-Protection: 1; mode=block');
    
    // Content Security Policy
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:;");
    
    // Referrer Policy
    header('Referrer-Policy: strict-origin-when-cross-origin');
    
    // Feature Policy
    header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
}

/**
 * Headers CORS para APIs
 */
function cors_headers() {
    if (headers_sent()) {
        return;
    }
    
    // Permitir origen específico en producción
    $allowed_origin = ENVIRONMENT === 'development' ? '*' : BASE_URL;
    
    header("Access-Control-Allow-Origin: $allowed_origin");
    header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type, X-Session-Token, Authorization");
    header("Access-Control-Max-Age: 3600");
    header("Access-Control-Allow-Credentials: true");
    
    // Manejar peticiones OPTIONS
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit;
    }
}

// ===========================
// RATE LIMITING
// ===========================

/**
 * Verificar rate limit
 */
function check_rate_limit($identifier, $max_attempts = null, $window = null) {
    if (!RATE_LIMIT_ENABLED) {
        return true;
    }
    
    $max_attempts = $max_attempts ?? RATE_LIMIT_REQUESTS;
    $window = $window ?? RATE_LIMIT_WINDOW;
    
    $cache_key = 'rate_limit_' . md5($identifier);
    $cache_file = TEMP_PATH . '/' . $cache_key . '.tmp';
    
    $attempts = [];
    if (file_exists($cache_file)) {
        $data = file_get_contents($cache_file);
        $attempts = json_decode($data, true) ?: [];
    }
    
    // Limpiar intentos antiguos
    $current_time = time();
    $attempts = array_filter($attempts, function($timestamp) use ($current_time, $window) {
        return ($current_time - $timestamp) < $window;
    });
    
    // Verificar límite
    if (count($attempts) >= $max_attempts) {
        return false;
    }
    
    // Agregar intento actual
    $attempts[] = $current_time;
    file_put_contents($cache_file, json_encode($attempts));
    
    return true;
}

// ===========================
// AUTENTICACIÓN API
// ===========================

/**
 * Verificar autenticación para APIs
 */
function verify_api_auth() {
    // Obtener token del header
    $headers = getallheaders();
    $token = '';
    
    // Buscar token en diferentes headers
    if (isset($headers['X-Session-Token'])) {
        $token = $headers['X-Session-Token'];
    } elseif (isset($headers['Authorization'])) {
        $auth = $headers['Authorization'];
        if (strpos($auth, 'Bearer ') === 0) {
            $token = substr($auth, 7);
        }
    } elseif (isset($_SERVER['HTTP_X_SESSION_TOKEN'])) {
        $token = $_SERVER['HTTP_X_SESSION_TOKEN'];
    }
    
    if (empty($token)) {
        return [
            'success' => false,
            'message' => 'Token de autenticación faltante'
        ];
    }
    
    try {
        require_once __DIR__ . '/database.php';
        $db = Database::getInstance();
        
        // Buscar sesión activa
        $stmt = $db->execute("
            SELECT 
                s.*,
                u.id as user_id,
                u.username,
                u.email,
                u.full_name,
                u.role,
                u.status,
                u.privileges
            FROM " . TABLE_SESSIONS . " s
            JOIN " . TABLE_USERS . " u ON u.id = s.user_id
            WHERE s.session_token = ? 
            AND s.is_active = 1
            AND u.active = 1
        ", [$token]);
        
        $session = $stmt->fetch();
        
        if (!$session) {
            return [
                'success' => false,
                'message' => 'Token inválido o expirado'
            ];
        }
        
        // Verificar expiración
        $last_activity = strtotime($session['last_activity']);
        $timeout = SESSION_LIFETIME * 60; // convertir a segundos
        
        if ((time() - $last_activity) > $timeout) {
            // Marcar sesión como inactiva
            $stmt = $db->execute(
                "UPDATE " . TABLE_SESSIONS . " SET is_active = 0 WHERE session_token = ?",
                [$token]
            );
            
            return [
                'success' => false,
                'message' => 'Sesión expirada'
            ];
        }
        
        // Actualizar última actividad
        $stmt = $db->execute(
            "UPDATE " . TABLE_SESSIONS . " SET last_activity = NOW() WHERE session_token = ?",
            [$token]
        );
        
        // Decodificar privilegios
        $privileges = json_decode($session['privileges'], true) ?: [];
        
        return [
            'success' => true,
            'user' => [
                'id' => (int)$session['user_id'],
                'username' => $session['username'],
                'email' => $session['email'],
                'full_name' => $session['full_name'],
                'role' => $session['role'],
                'privileges' => $privileges
            ],
            'session_id' => $session['id']
        ];
        
    } catch (Exception $e) {
        error_log("API Auth Error: " . $e->getMessage());
        return [
            'success' => false,
            'message' => 'Error de autenticación'
        ];
    }
}

// ===========================
// LOGGING Y SEGURIDAD
// ===========================

/**
 * Log de seguridad
 */
function security_log($event, $user_id = null, $details = []) {
    if (!LOG_SECURITY) {
        return;
    }
    
    try {
        require_once __DIR__ . '/database.php';
        $db = Database::getInstance();
        
        $log_data = [
            'event' => $event,
            'user_id' => $user_id,
            'ip_address' => get_client_ip(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'details' => json_encode($details),
            'timestamp' => date('Y-m-d H:i:s')
        ];
        
        // Intentar guardar en base de datos
        $stmt = $db->execute(
            "INSERT INTO " . TABLE_ACCESS_LOG . " (action, user_id, ip_address, user_agent, details, created_at) 
            VALUES (?, ?, ?, ?, ?, ?)",
            [
                $log_data['event'],
                $log_data['user_id'],
                $log_data['ip_address'],
                $log_data['user_agent'],
                $log_data['details'],
                $log_data['timestamp']
            ]
        );
        
    } catch (Exception $e) {
        // Si falla DB, guardar en archivo
        $log_file = LOG_PATH . '/security.log';
        $log_line = date('Y-m-d H:i:s') . " - " . json_encode($log_data) . PHP_EOL;
        error_log($log_line, 3, $log_file);
    }
}

// ===========================
// UTILIDADES
// ===========================

/**
 * Obtener IP real del cliente
 */
function get_client_ip() {
    $ip_keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    
    foreach ($ip_keys as $key) {
        if (array_key_exists($key, $_SERVER) === true) {
            foreach (explode(',', $_SERVER[$key]) as $ip) {
                $ip = trim($ip);
                
                if (validate_ip($ip) && 
                    !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * Obtener input JSON de la petición
 */
function get_json_input() {
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        return [];
    }
    
    return $data ?: [];
}

/**
 * Verificar IP en whitelist
 */
function check_ip_whitelist($ip, $whitelist = []) {
    if (empty($whitelist)) {
        return true; // Si no hay whitelist, permitir todas
    }
    
    foreach ($whitelist as $allowed_ip) {
        // Soporte para wildcards
        if ($allowed_ip === $ip || 
            (strpos($allowed_ip, '*') !== false && 
             fnmatch($allowed_ip, $ip))) {
            return true;
        }
        
        // Soporte para rangos CIDR
        if (strpos($allowed_ip, '/') !== false) {
            list($subnet, $bits) = explode('/', $allowed_ip);
            $ip_long = ip2long($ip);
            $subnet_long = ip2long($subnet);
            $mask = -1 << (32 - $bits);
            $subnet_long &= $mask;
            
            if (($ip_long & $mask) == $subnet_long) {
                return true;
            }
        }
    }
    
    return false;
}

/**
 * Cifrar datos sensibles
 */
function encrypt_data($data, $key = null) {
    if (!$key) {
        $key = ENCRYPTION_KEY;
    }
    
    $method = 'AES-256-CBC';
    $iv_length = openssl_cipher_iv_length($method);
    $iv = openssl_random_pseudo_bytes($iv_length);
    
    $encrypted = openssl_encrypt($data, $method, $key, 0, $iv);
    
    return base64_encode($encrypted . '::' . $iv);
}

/**
 * Descifrar datos
 */
function decrypt_data($encrypted_data, $key = null) {
    if (!$key) {
        $key = ENCRYPTION_KEY;
    }
    
    $method = 'AES-256-CBC';
    list($encrypted, $iv) = explode('::', base64_decode($encrypted_data), 2);
    
    return openssl_decrypt($encrypted, $method, $key, 0, $iv);
}

/**
 * Verificar permisos de usuario para una acción
 */
function check_permission($user_role, $required_permission) {
    return role_has_permission($user_role, $required_permission);
}

/**
 * Limpiar datos antiguos (para mantenimiento)
 */
function cleanup_old_data($table, $date_field, $days = 30) {
    try {
        require_once __DIR__ . '/database.php';
        $db = Database::getInstance();
        
        $stmt = $db->execute(
            "DELETE FROM $table WHERE $date_field < DATE_SUB(NOW(), INTERVAL ? DAY)",
            [$days]
        );
        
        return $stmt->rowCount();
        
    } catch (Exception $e) {
        error_log("Cleanup error: " . $e->getMessage());
        return false;
    }
}

// ===========================
// PREVENCIÓN DE ATAQUES
// ===========================

/**
 * Verificar y prevenir inyección SQL
 */
function prevent_sql_injection($value) {
    // PDO con prepared statements ya previene SQL injection
    // Esta función es para validación adicional
    
    if (is_string($value)) {
        // Remover caracteres peligrosos
        $value = str_replace(['--', '/*', '*/', 'xp_', 'sp_'], '', $value);
        
        // Verificar patrones sospechosos
        $suspicious_patterns = [
            '/union[\s\n]+select/i',
            '/select[\s\n]+.*from/i',
            '/insert[\s\n]+into/i',
            '/delete[\s\n]+from/i',
            '/drop[\s\n]+table/i',
            '/update[\s\n]+.*set/i'
        ];
        
        foreach ($suspicious_patterns as $pattern) {
            if (preg_match($pattern, $value)) {
                security_log('sql_injection_attempt', null, ['value' => $value]);
                return false;
            }
        }
    }
    
    return $value;
}

/**
 * Validar y limpiar nombres de archivo
 */
function sanitize_filename($filename) {
    // Remover caracteres especiales
    $filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);
    
    // Prevenir directory traversal
    $filename = str_replace(['..', '/', '\\'], '', $filename);
    
    // Limitar longitud
    if (strlen($filename) > 255) {
        $filename = substr($filename, 0, 255);
    }
    
    return $filename;
}

// Aplicar headers de seguridad si no se han enviado
if (!headers_sent()) {
    set_security_headers();
}
?>
