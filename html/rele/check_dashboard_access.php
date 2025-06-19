<?php
session_start();
header('Content-Type: application/json');

try {
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['role'])) {
        throw new Exception('No autorizado');
    }
    
    $allowed_roles = ['superUser', 'SupportUser', 'Admin'];
    
    if (!in_array($_SESSION['role'], $allowed_roles)) {
        throw new Exception('Acceso denegado. Rol insuficiente.');
    }
    
    echo json_encode([
        'success' => true,
        'role' => $_SESSION['role'],
        'username' => $_SESSION['username'] ?? 'Usuario'
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