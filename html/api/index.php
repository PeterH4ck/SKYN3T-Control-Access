<?php
// ===========================
// ARCHIVO: /var/www/html/api/index.php
// DESCRIPCIÓN: Documentación de APIs disponibles
// ===========================
?>
<?php
require_once '../includes/config.php';
require_once '../includes/database.php';
require_once '../includes/security.php';

// Headers
header('Content-Type: application/json; charset=UTF-8');
header('X-API-Version: 2.0.0');

// Permitir solo GET para documentación
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$base_url = 'http://' . $_SERVER['HTTP_HOST'] . '/api';

$api_documentation = [
    'name' => 'SKYN3T API',
    'version' => '2.0.0',
    'description' => 'Sistema de Control y Monitoreo - API RESTful',
    'base_url' => $base_url,
    'authentication' => [
        'type' => 'Session Token',
        'header' => 'X-Session-Token',
        'description' => 'Token obtenido al hacer login en /login/login.php'
    ],
    'endpoints' => [
        'authentication' => [
            [
                'method' => 'POST',
                'path' => '/login/login.php',
                'description' => 'Autenticación de usuario',
                'body' => [
                    'username' => 'string',
                    'password' => 'string'
                ],
                'response' => [
                    'success' => 'boolean',
                    'token' => 'string',
                    'user' => 'object'
                ]
            ],
            [
                'method' => 'GET',
                'path' => '/api/verify_session.php',
                'description' => 'Verificar sesión activa',
                'headers' => ['X-Session-Token'],
                'response' => [
                    'valid' => 'boolean',
                    'user' => 'object'
                ]
            ]
        ],
        'relay' => [
            [
                'method' => 'GET',
                'path' => '/api/relay/status.php',
                'description' => 'Obtener estado actual del relé',
                'headers' => ['X-Session-Token'],
                'response' => [
                    'success' => 'boolean',
                    'status' => 'on|off',
                    'last_change' => 'datetime',
                    'changed_by' => 'string'
                ]
            ],
            [
                'method' => 'POST',
                'path' => '/api/relay/control.php',
                'description' => 'Controlar el relé (ON/OFF)',
                'headers' => ['X-Session-Token'],
                'permissions' => ['Admin', 'SuperUser'],
                'body' => [
                    'action' => 'on|off|toggle',
                    'reason' => 'string (optional)'
                ],
                'response' => [
                    'success' => 'boolean',
                    'new_status' => 'on|off',
                    'message' => 'string'
                ]
            ]
        ],
        'devices' => [
            [
                'method' => 'GET',
                'path' => '/api/devices/list.php',
                'description' => 'Listar todos los dispositivos',
                'headers' => ['X-Session-Token'],
                'query_params' => [
                    'status' => 'active|inactive|all (optional)',
                    'type' => 'string (optional)',
                    'page' => 'integer (optional)',
                    'limit' => 'integer (optional)'
                ],
                'response' => [
                    'success' => 'boolean',
                    'devices' => 'array',
                    'total' => 'integer',
                    'page' => 'integer',
                    'pages' => 'integer'
                ]
            ],
            [
                'method' => 'POST',
                'path' => '/api/devices/add.php',
                'description' => 'Agregar nuevo dispositivo',
                'headers' => ['X-Session-Token'],
                'permissions' => ['Admin', 'SuperUser'],
                'body' => [
                    'name' => 'string',
                    'type' => 'string',
                    'mac_address' => 'string',
                    'ip_address' => 'string (optional)',
                    'location' => 'string (optional)',
                    'description' => 'string (optional)'
                ],
                'response' => [
                    'success' => 'boolean',
                    'device_id' => 'integer',
                    'message' => 'string'
                ]
            ],
            [
                'method' => 'PUT',
                'path' => '/api/devices/update.php',
                'description' => 'Actualizar dispositivo existente',
                'headers' => ['X-Session-Token'],
                'permissions' => ['Admin', 'SuperUser'],
                'body' => [
                    'device_id' => 'integer',
                    'name' => 'string (optional)',
                    'type' => 'string (optional)',
                    'mac_address' => 'string (optional)',
                    'ip_address' => 'string (optional)',
                    'location' => 'string (optional)',
                    'description' => 'string (optional)',
                    'status' => 'active|inactive (optional)'
                ],
                'response' => [
                    'success' => 'boolean',
                    'message' => 'string'
                ]
            ],
            [
                'method' => 'DELETE',
                'path' => '/api/devices/delete.php',
                'description' => 'Eliminar dispositivo',
                'headers' => ['X-Session-Token'],
                'permissions' => ['SuperUser'],
                'body' => [
                    'device_id' => 'integer'
                ],
                'response' => [
                    'success' => 'boolean',
                    'message' => 'string'
                ]
            ]
        ],
        'users' => [
            [
                'method' => 'GET',
                'path' => '/api/users/list.php',
                'description' => 'Listar todos los usuarios',
                'headers' => ['X-Session-Token'],
                'permissions' => ['Admin', 'SuperUser'],
                'query_params' => [
                    'role' => 'string (optional)',
                    'status' => 'active|inactive|all (optional)',
                    'page' => 'integer (optional)',
                    'limit' => 'integer (optional)'
                ],
                'response' => [
                    'success' => 'boolean',
                    'users' => 'array',
                    'total' => 'integer',
                    'page' => 'integer',
                    'pages' => 'integer'
                ]
            ],
            [
                'method' => 'POST',
                'path' => '/api/users/add.php',
                'description' => 'Agregar nuevo usuario',
                'headers' => ['X-Session-Token'],
                'permissions' => ['Admin', 'SuperUser'],
                'body' => [
                    'username' => 'string',
                    'password' => 'string',
                    'email' => 'string',
                    'full_name' => 'string',
                    'role' => 'User|SupportAdmin|Admin|SuperUser',
                    'phone' => 'string (optional)'
                ],
                'response' => [
                    'success' => 'boolean',
                    'user_id' => 'integer',
                    'message' => 'string'
                ]
            ],
            [
                'method' => 'PUT',
                'path' => '/api/users/update.php',
                'description' => 'Actualizar usuario existente',
                'headers' => ['X-Session-Token'],
                'permissions' => ['Admin', 'SuperUser'],
                'body' => [
                    'user_id' => 'integer',
                    'email' => 'string (optional)',
                    'full_name' => 'string (optional)',
                    'role' => 'string (optional)',
                    'phone' => 'string (optional)',
                    'status' => 'active|inactive (optional)',
                    'password' => 'string (optional)'
                ],
                'response' => [
                    'success' => 'boolean',
                    'message' => 'string'
                ]
            ],
            [
                'method' => 'DELETE',
                'path' => '/api/users/delete.php',
                'description' => 'Eliminar usuario',
                'headers' => ['X-Session-Token'],
                'permissions' => ['SuperUser'],
                'body' => [
                    'user_id' => 'integer'
                ],
                'response' => [
                    'success' => 'boolean',
                    'message' => 'string'
                ]
            ]
        ],
        'notifications' => [
            [
                'method' => 'GET',
                'path' => '/api/notifications/list.php',
                'description' => 'Listar notificaciones del usuario',
                'headers' => ['X-Session-Token'],
                'query_params' => [
                    'status' => 'read|unread|all (optional)',
                    'type' => 'string (optional)',
                    'page' => 'integer (optional)',
                    'limit' => 'integer (optional)'
                ],
                'response' => [
                    'success' => 'boolean',
                    'notifications' => 'array',
                    'unread_count' => 'integer',
                    'total' => 'integer',
                    'page' => 'integer',
                    'pages' => 'integer'
                ]
            ]
        ],
        'system' => [
            [
                'method' => 'GET',
                'path' => '/api/system/stats.php',
                'description' => 'Obtener estadísticas del sistema',
                'headers' => ['X-Session-Token'],
                'permissions' => ['Admin', 'SuperUser'],
                'response' => [
                    'success' => 'boolean',
                    'stats' => [
                        'total_users' => 'integer',
                        'active_sessions' => 'integer',
                        'total_devices' => 'integer',
                        'relay_changes_today' => 'integer',
                        'system_uptime' => 'string',
                        'database_size' => 'string'
                    ]
                ]
            ],
            [
                'method' => 'GET',
                'path' => '/api/system/health.php',
                'description' => 'Estado de salud del sistema',
                'headers' => ['X-Session-Token'],
                'response' => [
                    'success' => 'boolean',
                    'status' => 'healthy|warning|critical',
                    'components' => [
                        'database' => 'object',
                        'session_manager' => 'object',
                        'relay_controller' => 'object',
                        'file_system' => 'object'
                    ]
                ]
            ],
            [
                'method' => 'GET',
                'path' => '/api/system/logs.php',
                'description' => 'Acceso a logs del sistema',
                'headers' => ['X-Session-Token'],
                'permissions' => ['SuperUser'],
                'query_params' => [
                    'type' => 'access|error|security|all (optional)',
                    'date' => 'YYYY-MM-DD (optional)',
                    'user_id' => 'integer (optional)',
                    'page' => 'integer (optional)',
                    'limit' => 'integer (optional)'
                ],
                'response' => [
                    'success' => 'boolean',
                    'logs' => 'array',
                    'total' => 'integer',
                    'page' => 'integer',
                    'pages' => 'integer'
                ]
            ]
        ]
    ],
    'error_codes' => [
        '400' => 'Bad Request - Invalid parameters',
        '401' => 'Unauthorized - Invalid or missing token',
        '403' => 'Forbidden - Insufficient permissions',
        '404' => 'Not Found - Resource not found',
        '405' => 'Method Not Allowed',
        '429' => 'Too Many Requests - Rate limit exceeded',
        '500' => 'Internal Server Error'
    ],
    'rate_limiting' => [
        'requests_per_minute' => 60,
        'requests_per_hour' => 1000,
        'burst_limit' => 10
    ]
];

echo json_encode($api_documentation, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
