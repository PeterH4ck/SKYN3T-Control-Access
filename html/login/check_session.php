<?php
/**
 * SKYN3T - Verificación de Sesión
 * Archivo: /var/www/html/login/check_session.php
 * Endpoint para verificar y validar sesiones activas
 * 
 * @version 2.0
 * @author SKYN3T Team
 * @database skyn3t_db (MariaDB)
 */

// Inicializar sistema
require_once '/var/www/html/includes/init.php';

// Headers de API y seguridad
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');

// Manejar preflight CORS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Permitir GET y POST para flexibilidad
if (!in_array($_SERVER['REQUEST_METHOD'], ['GET', 'POST'])) {
    sendErrorResponse('Método no permitido. Use GET o POST para verificar sesión.', 405, 'METHOD_NOT_ALLOWED');
}

try {
    // Obtener IP del cliente para verificaciones de seguridad
    $clientIP = getClientIP();
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    
    // Inicializar sistema de autenticación
    $auth = new Auth();
    
    // Verificar sesión
    $sessionResult = $auth->verifySession();
    
    if ($sessionResult['valid']) {
        // Sesión válida
        $user = $sessionResult['user'];
        
        // Verificaciones adicionales de seguridad
        $securityChecks = performSecurityChecks($user, $clientIP, $userAgent);
        
        // Registrar verificación exitosa (solo en debug)
        if (isDebugMode()) {
            writeLog('debug', 'Verificación de sesión exitosa', [
                'user_id' => $user['id'],
                'username' => $user['username'],
                'ip' => $clientIP,
                'user_agent' => substr($userAgent, 0, 100)
            ]);
        }
        
        // Respuesta exitosa con información completa
        sendSuccessResponse([
            'valid' => true,
            'authenticated' => true,
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'name' => $user['name'],
                'email' => $user['email'],
                'role' => $user['role'],
                'privileges' => $user['privileges'],
                'role_info' => [
                    'name' => SystemConfig::ROLES[$user['role']]['name'] ?? $user['role'],
                    'description' => SystemConfig::ROLES[$user['role']]['description'] ?? '',
                    'permissions' => SystemConfig::ROLES[$user['role']]['permissions'] ?? []
                ]
            ],
            'session' => [
                'token' => $sessionResult['session']['token'],
                'expires_at' => $sessionResult['session']['expires_at'],
                'time_remaining' => strtotime($sessionResult['session']['expires_at']) - time(),
                'auto_extended' => true
            ],
            'redirect_url' => $sessionResult['redirect_url'],
            'security' => $securityChecks,
            'system' => [
                'name' => SystemConfig::SYSTEM_NAME,
                'version' => SystemConfig::SYSTEM_VERSION,
                'server_time' => date('Y-m-d H:i:s'),
                'timezone' => SystemConfig::UI_TIMEZONE
            ],
            'permissions' => [
                'available' => getRolePermissions($user['role']),
                'user_specific' => $user['privileges']
            ]
        ], 'Sesión válida y activa');
        
    } else {
        // Sesión inválida o expirada
        
        // Registrar verificación fallida
        writeLog('info', 'Verificación de sesión fallida', [
            'reason' => $sessionResult['message'],
            'ip' => $clientIP,
            'user_agent' => substr($userAgent, 0, 100)
        ]);
        
        // Limpiar posibles datos de sesión locales
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
        
        // Respuesta de sesión inválida
        sendJSONResponse([
            'success' => false,
            'valid' => false,
            'authenticated' => false,
            'message' => $sessionResult['message'],
            'error_code' => 'SESSION_INVALID',
            'actions' => [
                'login' => '/login/index_login.html',
                'redirect' => '/login/index_login.html'
            ],
            'system' => [
                'name' => SystemConfig::SYSTEM_NAME,
                'server_time' => date('Y-m-d H:i:s')
            ],
            'timestamp' => date('c')
        ], 401);
    }
    
} catch (Exception $e) {
    // Error del sistema
    writeLog('error', 'Error crítico en verificación de sesión: ' . $e->getMessage(), [
        'ip' => $clientIP ?? 'unknown',
        'user_agent' => substr($userAgent ?? 'unknown', 0, 100),
        'error_trace' => $e->getTraceAsString()
    ]);
    
    sendErrorResponse(
        'Error interno del sistema durante verificación de sesión', 
        500, 
        'SESSION_CHECK_ERROR'
    );
}

/**
 * Realizar verificaciones adicionales de seguridad
 */
function performSecurityChecks($user, $clientIP, $userAgent) {
    $checks = [
        'ip_change_detected' => false,
        'user_agent_change_detected' => false,
        'suspicious_activity' => false,
        'session_hijack_risk' => false,
        'last_activity' => date('Y-m-d H:i:s'),
        'security_score' => 100
    ];
    
    try {
        $db = Database::getInstance();
        
        // Verificar cambio de IP (obtener última IP conocida)
        $lastSession = $db->fetchOne("
            SELECT ip_address, user_agent, created_at 
            FROM sessions 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 1
        ", [$user['id']]);
        
        if ($lastSession) {
            // Verificar cambio de IP
            if ($lastSession['ip_address'] !== $clientIP) {
                $checks['ip_change_detected'] = true;
                $checks['security_score'] -= 20;
                
                writeLog('warning', 'Cambio de IP detectado en sesión', [
                    'user_id' => $user['id'],
                    'username' => $user['username'],
                    'old_ip' => $lastSession['ip_address'],
                    'new_ip' => $clientIP
                ]);
            }
            
            // Verificar cambio drástico de User Agent
            $similarity = similar_text($lastSession['user_agent'], $userAgent);
            if ($similarity < 50) { // Menos del 50% de similitud
                $checks['user_agent_change_detected'] = true;
                $checks['security_score'] -= 15;
                
                writeLog('warning', 'Cambio de User Agent detectado', [
                    'user_id' => $user['id'],
                    'username' => $user['username'],
                    'similarity' => $similarity
                ]);
            }
        }
        
        // Verificar actividad sospechosa reciente
        $recentFailedAttempts = $db->fetchOne("
            SELECT COUNT(*) as count 
            FROM access_log 
            WHERE user_id = ? 
            AND action = 'failed_login' 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
        ", [$user['id']]);
        
        if ($recentFailedAttempts['count'] > 3) {
            $checks['suspicious_activity'] = true;
            $checks['security_score'] -= 25;
        }
        
        // Calcular riesgo de secuestro de sesión
        $riskFactors = 0;
        if ($checks['ip_change_detected']) $riskFactors++;
        if ($checks['user_agent_change_detected']) $riskFactors++;
        if ($checks['suspicious_activity']) $riskFactors++;
        
        if ($riskFactors >= 2) {
            $checks['session_hijack_risk'] = true;
            $checks['security_score'] -= 30;
            
            // Crear notificación de seguridad
            createNotification(
                'security',
                'Posible Secuestro de Sesión Detectado',
                "Actividad sospechosa detectada en la cuenta de {$user['username']}",
                $user['id']
            );
        }
        
        // Asegurar que el puntaje no sea negativo
        $checks['security_score'] = max(0, $checks['security_score']);
        
    } catch (Exception $e) {
        writeLog('error', 'Error en verificaciones de seguridad: ' . $e->getMessage());
        $checks['error'] = 'No se pudieron completar todas las verificaciones de seguridad';
    }
    
    return $checks;
}

/**
 * Función para limpiar sesiones expiradas automáticamente
 */
function cleanupExpiredSessionsIfNeeded() {
    // Solo limpiar ocasionalmente para no sobrecargar
    if (rand(1, 100) <= 5) { // 5% de probabilidad
        try {
            $db = Database::getInstance();
            $deleted = $db->prepare("DELETE FROM sessions WHERE expires_at <= NOW()");
            
            if ($deleted) {
                writeLog('info', 'Limpieza automática de sesiones expiradas ejecutada');
            }
        } catch (Exception $e) {
            writeLog('error', 'Error en limpieza automática de sesiones: ' . $e->getMessage());
        }
    }
}

// Ejecutar limpieza ocasional
cleanupExpiredSessionsIfNeeded();

/**
 * Función para obtener estadísticas de sesión (solo para debug)
 */
function getSessionStats() {
    if (!isDebugMode()) {
        return null;
    }
    
    try {
        $db = Database::getInstance();
        
        $stats = $db->fetchOne("
            SELECT 
                COUNT(*) as total_sessions,
                COUNT(CASE WHEN expires_at > NOW() THEN 1 END) as active_sessions,
                COUNT(CASE WHEN expires_at <= NOW() THEN 1 END) as expired_sessions
            FROM sessions
        ");
        
        return $stats;
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

// Agregar estadísticas en modo debug
if (isDebugMode() && isset($_GET['debug_stats'])) {
    $stats = getSessionStats();
    if ($stats) {
        writeLog('debug', 'Estadísticas de sesiones', $stats);
    }
}
?>