<?php
/**
 * Verificación de acceso específica para gestión de residentes
 * Solo permite acceso a SuperUser, SupportUser y Admin
 */

session_start();
header('Content-Type: application/json');

try {
    // Verificar si hay sesión activa
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['role'])) {
        throw new Exception('No autorizado - Sesión no válida');
    }
    
    // Verificar roles permitidos para gestión de residentes
    $allowed_roles = ['superUser', 'SupportUser', 'Admin'];
    
    if (!in_array($_SESSION['role'], $allowed_roles)) {
        throw new Exception('Acceso denegado - Esta función requiere permisos de administrador');
    }
    
    // Verificar que la sesión no haya expirado
    $session_timeout = 3600; // 1 hora
    if (isset($_SESSION['login_time'])) {
        $session_age = time() - $_SESSION['login_time'];
        if ($session_age > $session_timeout) {
            session_unset();
            session_destroy();
            throw new Exception('Sesión expirada');
        }
    }
    
    // Verificar IP para prevenir secuestro de sesión
    if (isset($_SESSION['ip']) && $_SESSION['ip'] !== $_SERVER['REMOTE_ADDR']) {
        session_unset();
        session_destroy();
        throw new Exception('Sesión comprometida - IP diferente');
    }
    
    // Acceso autorizado
    echo json_encode([
        'success' => true,
        'role' => $_SESSION['role'],
        'username' => $_SESSION['username'] ?? 'Usuario',
        'permissions' => [
            'view_residents' => true,
            'create_residents' => true,
            'edit_residents' => true,
            'delete_residents' => $_SESSION['role'] === 'superUser',
            'manage_requests' => true,
            'export_data' => $_SESSION['role'] !== 'SupportUser'
        ]
    ]);
    
} catch (Exception $e) {
    http_response_code(403);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage(),
        'redirect' => '/rele/index_rele.html'
    ]);
}
?>