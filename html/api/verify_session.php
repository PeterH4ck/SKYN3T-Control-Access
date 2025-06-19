<?php
/**
 * Archivo: /var/www/html/api/verify_session.php
 * API endpoint para verificación de sesión mejorado
 */

// Definir constante del sistema
define('SKYN3T_SYSTEM', true);

// Headers de seguridad y CORS
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Manejo de solicitudes OPTIONS (CORS preflight)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Solo permitir POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'valid' => false,
        'message' => 'Método no permitido',
        'error_code' => 'METHOD_NOT_ALLOWED'
    ]);
    exit;
}

// Incluir sistema de autenticación
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/database.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/session.php';

try {
    // Obtener token de diferentes fuentes
    $token = null;
    
    // 1. Header Authorization
    $headers = getallheaders();
    if ($headers && isset($headers['Authorization'])) {
        if (preg_match('/Bearer\s+(.*)$/i', $headers['Authorization'], $matches)) {
            $token = trim($matches[1]);
        }
    }
    
    // 2. Body JSON
    if (!$token) {
        $input = json_decode(file_get_contents('php://input'), true);
        $token = $input['token'] ?? null;
    }
    
    // 3. Parámetros POST
    if (!$token) {
        $token = $_POST['token'] ?? null;
    }
    
    // 4. Sesión PHP
    if (!$token) {
        $sessionManager = getSessionManager();
        if (isLoggedIn()) {
            $token = $_SESSION['session_token'] ?? null;
        }
    }
    
    if (!$token) {
        http_response_code(401);
        echo json_encode([
            'success' => false,
            'valid' => false,
            'authenticated' => false,
            'message' => 'Token de sesión no proporcionado',
            'error_code' => 'TOKEN_MISSING'
        ]);
        exit;
    }
    
    // Verificar sesión usando el sistema de autenticación
    $auth = Auth::getInstance();
    $sessionResult = $auth->verifySession($token);
    
    if (!$sessionResult['valid']) {
        http_response_code(401);
        echo json_encode([
            'success' => false,
            'valid' => false,
            'authenticated' => false,
            'message' => $sessionResult['message'],
            'error_code' => 'SESSION_INVALID'
        ]);
        exit;
    }
    
    // Preparar respuesta exitosa
    $response = [
        'success' => true,
        'valid' => true,
        'authenticated' => true,
        'user' => $sessionResult['user'],
        'session' => $sessionResult['session'],
        'permissions' => $sessionResult['user']['privileges'],
        'server_time' => date('Y-m-d H:i:s'),
        'token_expires_in' => strtotime($sessionResult['session']['expires_at']) - time()
    ];
    
    // Agregar información de redirección según el rol
    $userRole = $sessionResult['user']['role'];
    switch ($userRole) {
        case 'SuperUser':
        case 'Admin':
        case 'SupportAdmin':
            $response['redirect_url'] = '/dashboard/index.php';
            break;
        case 'User':
            $response['redirect_url'] = '/input_data.html';
            break;
        default:
            $response['redirect_url'] = '/dashboard/index.php';
    }
    
    // Log de verificación exitosa
    Security::logSecurityEvent('session_verified_api', [
        'user_id' => $sessionResult['user']['id'],
        'username' => $sessionResult['user']['username'],
        'role' => $userRole,
        'token_preview' => substr($token, 0, 8) . '...'
    ], 'INFO');
    
    echo json_encode($response);
    
} catch (Exception $e) {
    error_log("Error en verify_session API: " . $e->getMessage());
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'valid' => false,
        'authenticated' => false,
        'message' => 'Error interno del servidor',
        'error_code' => 'INTERNAL_ERROR'
    ]);
}
?>
