<?php
/**
 * Verificación de acceso EXCLUSIVO para administración total del sistema
 * Solo permite acceso al usuario 'peterh4ck'
 * Versión: 3.0.1 - Sistema de Administración Total
 */

session_start();
header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');

try {
    // Verificar si hay sesión activa
    if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
        throw new Exception('No hay sesión activa');
    }

    // Verificar tiempo de sesión (8 horas)
    if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > 28800) {
        session_destroy();
        throw new Exception('Sesión expirada');
    }

    // VERIFICACIÓN ESTRICTA: Solo peterh4ck puede acceder
    $username = $_SESSION['username'] ?? '';
    $role = $_SESSION['role'] ?? 'User';
    $user_id = $_SESSION['user_id'] ?? null;

    if ($username !== 'peterh4ck') {
        throw new Exception('Acceso DENEGADO. Esta área es exclusiva para el administrador principal.');
    }

    // Verificar que el rol sea SuperUser
    if ($role !== 'SuperUser') {
        throw new Exception('Permisos insuficientes. Se requiere rol SuperUser.');
    }

    // Verificar IP para prevenir secuestro de sesión
    if (isset($_SESSION['ip']) && $_SESSION['ip'] !== $_SERVER['REMOTE_ADDR']) {
        error_log("SECURITY ALERT: IP mismatch for peterh4ck: session IP {$_SESSION['ip']}, current IP {$_SERVER['REMOTE_ADDR']}");
        // Para peterh4ck, solo loggeamos pero no bloqueamos (puede usar diferentes dispositivos)
    }

    // Permisos totales para peterh4ck
    $full_permissions = [
        'database_admin' => true,
        'user_management' => true,
        'role_management' => true,
        'permission_management' => true,
        'system_configuration' => true,
        'backup_management' => true,
        'security_logs' => true,
        'table_management' => true,
        'sql_execution' => true,
        'schema_modification' => true,
        'data_export' => true,
        'data_import' => true,
        'system_monitoring' => true,
        'emergency_access' => true,
        'delete_users' => true,
        'modify_permissions' => true,
        'create_admins' => true,
        'view_all_data' => true,
        'modify_all_data' => true,
        'system_maintenance' => true
    ];

    // Acceso TOTAL autorizado
    echo json_encode([
        'success' => true,
        'username' => $username,
        'user_id' => $user_id,
        'role' => $role,
        'access_level' => 'TOTAL_ADMIN',
        'permissions' => $full_permissions,
        'session_info' => [
            'login_time' => $_SESSION['login_time'] ?? time(),
            'last_activity' => time(),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ],
        'system_info' => [
            'php_version' => PHP_VERSION,
            'server_time' => date('Y-m-d H:i:s'),
            'session_id' => session_id()
        ]
    ]);

} catch (Exception $e) {
    http_response_code(403);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage(),
        'redirect' => '/rele/index_rele.html',
        'security_info' => [
            'attempted_user' => $_SESSION['username'] ?? 'unknown',
            'attempted_role' => $_SESSION['role'] ?? 'unknown',
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'timestamp' => date('Y-m-d H:i:s'),
            'required_user' => 'peterh4ck',
            'required_role' => 'SuperUser'
        ]
    ]);
    
    // Log de seguridad
    error_log("UNAUTHORIZED ADMIN ACCESS ATTEMPT: " . json_encode([
        'user' => $_SESSION['username'] ?? 'unknown',
        'role' => $_SESSION['role'] ?? 'unknown',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'time' => date('Y-m-d H:i:s')
    ]));
}
?>