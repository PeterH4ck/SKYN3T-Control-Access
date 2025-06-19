<?php
/**
 * SKYN3T - Verificación de Acceso al Dashboard
 * Versión: 2.3.0
 * Verifica que el usuario tenga permisos para acceder al dashboard
 */

session_start();
header('Content-Type: application/json');

// Verificar si hay sesión activa
if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
    echo json_encode([
        'success' => false,
        'message' => 'No hay sesión activa',
        'redirect' => '/login/index_login.html'
    ]);
    exit;
}

// Verificar tiempo de sesión (opcional - 8 horas)
if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > 28800) {
    session_destroy();
    echo json_encode([
        'success' => false,
        'message' => 'Sesión expirada',
        'redirect' => '/login/index_login.html'
    ]);
    exit;
}

// Obtener rol del usuario
$role = $_SESSION['role'] ?? 'User';

// Roles permitidos para el dashboard
$allowed_roles = ['SuperUser', 'Admin', 'SupportAdmin'];

// Verificar si el rol tiene acceso
if (!in_array($role, $allowed_roles)) {
    echo json_encode([
        'success' => false,
        'message' => 'No tienes permisos para acceder al dashboard administrativo',
        'redirect' => '/input_data/input.html', // Redirigir a la página de usuarios básicos
        'role' => $role
    ]);
    exit;
}

// Si llegamos aquí, el acceso está permitido
echo json_encode([
    'success' => true,
    'message' => 'Acceso autorizado',
    'user' => [
        'id' => $_SESSION['user_id'] ?? null,
        'username' => $_SESSION['username'] ?? 'Usuario',
        'role' => $role
    ],
    'permissions' => getPermissionsByRole($role)
]);

/**
 * Obtener permisos según el rol
 */
function getPermissionsByRole($role) {
    $permissions = [
        'SuperUser' => [
            'dashboard' => true,
            'devices' => ['view', 'add', 'edit', 'delete'],
            'users' => ['view', 'add', 'edit', 'delete'],
            'settings' => ['view', 'edit'],
            'logs' => ['view', 'export'],
            'relay' => ['control', 'schedule'],
            'statistics' => true,
            'system' => true
        ],
        'Admin' => [
            'dashboard' => true,
            'devices' => ['view', 'add', 'edit', 'delete'],
            'users' => ['view', 'add', 'edit'],
            'settings' => ['view', 'edit'],
            'logs' => ['view'],
            'relay' => ['control', 'schedule'],
            'statistics' => true,
            'system' => false
        ],
        'SupportAdmin' => [
            'dashboard' => true,
            'devices' => ['view', 'edit'],
            'users' => ['view'],
            'settings' => ['view'],
            'logs' => ['view'],
            'relay' => ['control'],
            'statistics' => true,
            'system' => false
        ],
        'User' => [
            'dashboard' => false,
            'devices' => ['view'],
            'users' => false,
            'settings' => false,
            'logs' => false,
            'relay' => ['control'],
            'statistics' => false,
            'system' => false
        ]
    ];
    
    return $permissions[$role] ?? $permissions['User'];
}
?>
