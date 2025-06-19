<?php
/**
 * Archivo: /var/www/html/api/index.php
 * Documentación e información de las APIs de SKYN3T
 */

// Definir constante del sistema
define('SKYN3T_SYSTEM', true);

// Incluir archivos del sistema
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/database.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/session.php';

// Configurar headers
header('Content-Type: text/html; charset=UTF-8');

// Verificar si es una petición de información de APIs
if (isset($_GET['format']) && $_GET['format'] === 'json') {
    header('Content-Type: application/json');
    
    $apiInfo = [
        'name' => 'SKYN3T API',
        'version' => '2.0.0',
        'description' => 'API REST para el sistema de control SKYN3T',
        'base_url' => getBaseUrl() . '/api',
        'authentication' => 'Bearer Token',
        'timestamp' => date('Y-m-d H:i:s'),
        'endpoints' => [
            'authentication' => [
                'verify_session' => [
                    'method' => 'POST',
                    'url' => '/api/verify_session.php',
                    'description' => 'Verificar token de sesión',
                    'auth_required' => true
                ]
            ],
            'relay_control' => [
                'status' => [
                    'method' => 'GET',
                    'url' => '/api/relay/status.php',
                    'description' => 'Obtener estado actual del relé',
                    'auth_required' => false
                ],
                'control' => [
                    'method' => 'POST',
                    'url' => '/api/relay/control.php',
                    'description' => 'Controlar relé (ON/OFF)',
                    'auth_required' => true,
                    'permissions' => ['control_relay']
                ]
            ],
            'devices' => [
                'list' => [
                    'method' => 'GET',
                    'url' => '/api/devices/list.php',
                    'description' => 'Listar dispositivos',
                    'auth_required' => true,
                    'permissions' => ['view_devices']
                ],
                'add' => [
                    'method' => 'POST',
                    'url' => '/api/devices/add.php',
                    'description' => 'Agregar nuevo dispositivo',
                    'auth_required' => true,
                    'permissions' => ['manage_devices']
                ],
                'update' => [
                    'method' => 'PUT',
                    'url' => '/api/devices/update.php',
                    'description' => 'Actualizar dispositivo',
                    'auth_required' => true,
                    'permissions' => ['manage_devices']
                ],
                'delete' => [
                    'method' => 'DELETE',
                    'url' => '/api/devices/delete.php',
                    'description' => 'Eliminar dispositivo',
                    'auth_required' => true,
                    'permissions' => ['manage_devices']
                ]
            ],
            'users' => [
                'list' => [
                    'method' => 'GET',
                    'url' => '/api/users/list.php',
                    'description' => 'Listar usuarios',
                    'auth_required' => true,
                    'permissions' => ['manage_users']
                ],
                'profile' => [
                    'method' => 'GET',
                    'url' => '/api/users/profile.php',
                    'description' => 'Obtener perfil del usuario actual',
                    'auth_required' => true
                ]
            ],
            'notifications' => [
                'list' => [
                    'method' => 'GET',
                    'url' => '/api/notifications/list.php',
                    'description' => 'Listar notificaciones',
                    'auth_required' => true
                ]
            ],
            'system' => [
                'stats' => [
                    'method' => 'GET',
                    'url' => '/api/system/stats.php',
                    'description' => 'Estadísticas del sistema',
                    'auth_required' => true,
                    'permissions' => ['view_stats']
                ],
                'health' => [
                    'method' => 'GET',
                    'url' => '/api/system/health.php',
                    'description' => 'Estado de salud del sistema',
                    'auth_required' => false
                ]
            ]
        ]
    ];
    
    echo json_encode($apiInfo, JSON_PRETTY_PRINT);
    exit;
}

// Obtener estadísticas básicas
try {
    $db = Database::getInstance();
    $sessionManager = getSessionManager();
    
    $stats = [
        'total_users' => $db->fetch("SELECT COUNT(*) as count FROM users WHERE active = 1")['count'],
        'active_sessions' => $sessionManager->getSessionStats()['active_sessions'],
        'total_devices' => $db->fetch("SELECT COUNT(*) as count FROM devices WHERE status = 'active'")['count'],
        'relay_status' => $db->fetch("SELECT relay_state, led_state FROM relay_status ORDER BY timestamp DESC LIMIT 1")
    ];
} catch (Exception $e) {
    $stats = [
        'error' => 'Unable to load stats'
    ];
}

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SKYN3T API Documentation</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            min-height: 100vh;
            padding: 20px;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: #111;
            padding: 30px;
            border-radius: 10px;
            border: 1px solid #333;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.1);
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 1px solid #333;
            padding-bottom: 20px;
        }
        
        .header h1 {
            font-size: 2.5em;
            color: #00ff00;
            text-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            color: #888;
            font-size: 1.1em;
            margin-bottom: 20px;
        }
        
        .api-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .info-box {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #333;
            text-align: center;
        }
        
        .info-value {
            font-size: 1.8em;
            color: #00ff00;
            font-weight: bold;
        }
        
        .info-label {
            color: #888;
            font-size: 0.9em;
            margin-top: 5px;
        }
        
        .section {
            margin-bottom: 30px;
            background: #0f0f0f;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #00ff00;
        }
        
        .section h2 {
            color: #00ff00;
            margin-bottom: 20px;
            font-size: 1.5em;
        }
        
        .endpoint-group {
            margin-bottom: 25px;
            background: #1a1a1a;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #333;
        }
        
        .group-title {
            color: #ffff00;
            font-size: 1.2em;
            margin-bottom: 15px;
            font-weight: bold;
        }
        
        .endpoint {
            margin-bottom: 15px;
            padding: 12px;
            background: #222;
            border-radius: 4px;
            border-left: 3px solid #00ff00;
        }
        
        .endpoint-header {
            display: flex;
            align-items: center;
            margin-bottom: 8px;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .method {
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.8em;
            min-width: 60px;
            text-align: center;
        }
        
        .method.GET { background: #2d5a2d; color: #90EE90; }
        .method.POST { background: #5a5a2d; color: #FFD700; }
        .method.PUT { background: #2d4a5a; color: #87CEEB; }
        .method.DELETE { background: #5a2d2d; color: #FFB6C1; }
        
        .endpoint-url {
            color: #00ffff;
            font-family: monospace;
            background: #333;
            padding: 2px 6px;
            border-radius: 3px;
            flex: 1;
        }
        
        .auth-required {
            background: #4a2d2d;
            color: #FFB6C1;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.8em;
        }
        
        .endpoint-desc {
            color: #ccc;
            font-size: 0.9em;
            margin-bottom: 8px;
        }
        
        .permissions {
            font-size: 0.8em;
            color: #888;
        }
        
        .permissions strong {
            color: #00ff00;
        }
        
        .quick-test {
            background: #2d2d5a;
            padding: 15px;
            border-radius: 6px;
            margin-top: 30px;
        }
        
        .quick-test h3 {
            color: #87CEEB;
            margin-bottom: 15px;
        }
        
        .test-command {
            background: #000;
            padding: 10px;
            border-radius: 4px;
            color: #00ff00;
            font-family: monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin-bottom: 10px;
            border: 1px solid #333;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-online { background: #00ff00; box-shadow: 0 0 5px rgba(0, 255, 0, 0.5); }
        .status-offline { background: #ff4444; box-shadow: 0 0 5px rgba(255, 68, 68, 0.5); }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #333;
            color: #666;
        }
        
        .json-link {
            display: inline-block;
            margin-top: 15px;
            padding: 8px 15px;
            background: #2d5a2d;
            color: #90EE90;
            text-decoration: none;
            border-radius: 4px;
            border: 1px solid #4a8a4a;
            transition: all 0.3s ease;
        }
        
        .json-link:hover {
            background: #4a8a4a;
            box-shadow: 0 0 10px rgba(0, 255, 0, 0.3);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SKYN3T API</h1>
            <p class="subtitle">API REST para Sistema de Control y Monitoreo</p>
            <div class="api-info">
                <div class="info-box">
                    <div class="info-value">v2.0.0</div>
                    <div class="info-label">Versión</div>
                </div>
                <div class="info-box">
                    <div class="info-value"><?php echo $stats['total_users'] ?? '?'; ?></div>
                    <div class="info-label">Usuarios Activos</div>
                </div>
                <div class="info-box">
                    <div class="info-value"><?php echo $stats['active_sessions'] ?? '?'; ?></div>
                    <div class="info-label">Sesiones Activas</div>
                </div>
                <div class="info-box">
                    <div class="info-value"><?php echo $stats['total_devices'] ?? '?'; ?></div>
                    <div class="info-label">Dispositivos</div>
                </div>
                <div class="info-box">
                    <div class="info-value">
                        <span class="status-indicator <?php echo ($stats['relay_status']['relay_state'] ?? false) ? 'status-online' : 'status-offline'; ?>"></span>
                        <?php echo ($stats['relay_status']['relay_state'] ?? false) ? 'ON' : 'OFF'; ?>
                    </div>
                    <div class="info-label">Estado del Relé</div>
                </div>
            </div>
            <a href="?format=json" class="json-link">📄 Ver Documentación JSON</a>
        </div>

        <!-- Autenticación -->
        <div class="section">
            <h2>🔐 Autenticación</h2>
            <div class="endpoint-group">
                <div class="group-title">Session Management</div>
                
                <div class="endpoint">
                    <div class="endpoint-header">
                        <span class="method POST">POST</span>
                        <span class="endpoint-url">/api/verify_session.php</span>
                        <span class="auth-required">Auth Required</span>
                    </div>
                    <div class="endpoint-desc">Verificar validez del token de sesión</div>
                    <div class="permissions"><strong>Headers:</strong> Authorization: Bearer {token}</div>
                </div>
            </div>
        </div>

        <!-- Control de Relé -->
        <div class="section">
            <h2>⚡ Control de Relé</h2>
            <div class="endpoint-group">
                <div class="group-title">Relay Operations</div>
                
                <div class="endpoint">
                    <div class="endpoint-header">
                        <span class="method GET">GET</span>
                        <span class="endpoint-url">/api/relay/status.php</span>
                    </div>
                    <div class="endpoint-desc">Obtener estado actual del relé y LED</div>
                </div>

                <div class="endpoint">
                    <div class="endpoint-header">
                        <span class="method POST">POST</span>
                        <span class="endpoint-url">/api/relay/control.php</span>
                        <span class="auth-required">Auth Required</span>
                    </div>
                    <div class="endpoint-desc">Controlar estado del relé (ON/OFF)</div>
                    <div class="permissions"><strong>Permisos:</strong> control_relay</div>
                </div>
            </div>
        </div>

        <!-- Gestión de Dispositivos -->
        <div class="section">
            <h2>📱 Gestión de Dispositivos</h2>
            <div class="endpoint-group">
                <div class="group-title">Device Management</div>
                
                <div class="endpoint">
                    <div class="endpoint-header">
                        <span class="method GET">GET</span>
                        <span class="endpoint-url">/api/devices/list.php</span>
                        <span class="auth-required">Auth Required</span>
                    </div>
                    <div class="endpoint-desc">Listar todos los dispositivos registrados</div>
                    <div class="permissions"><strong>Permisos:</strong> view_devices</div>
                </div>

                <div class="endpoint">
                    <div class="endpoint-header">
                        <span class="method POST">POST</span>
                        <span class="endpoint-url">/api/devices/add.php</span>
                        <span class="auth-required">Auth Required</span>
                    </div>
                    <div class="endpoint-desc">Agregar nuevo dispositivo al sistema</div>
                    <div class="permissions"><strong>Permisos:</strong> manage_devices</div>
                </div>

                <div class="endpoint">
                    <div class="endpoint-header">
                        <span class="method PUT">PUT</span>
                        <span class="endpoint-url">/api/devices/update.php</span>
                        <span class="auth-required">Auth Required</span>
                    </div>
                    <div class="endpoint-desc">Actualizar información de dispositivo</div>
                    <div class="permissions"><strong>Permisos:</strong> manage_devices</div>
                </div>

                <div class="endpoint">
                    <div class="endpoint-header">
                        <span class="method DELETE">DELETE</span>
                        <span class="endpoint-url">/api/devices/delete.php</span>
                        <span class="auth-required">Auth Required</span>
                    </div>
                    <div class="endpoint-desc">Eliminar dispositivo del sistema</div>
                    <div class="permissions"><strong>Permisos:</strong> manage_devices</div>
                </div>
            </div>
        </div>

        <!-- Gestión de Usuarios -->
        <div class="section">
            <h2>👥 Gestión de Usuarios</h2>
            <div class="endpoint-group">
                <div class="group-title">User Management</div>
                
                <div class="endpoint">
                    <div class="endpoint-header">
                        <span class="method GET">GET</span>
                        <span class="endpoint-url">/api/users/list.php</span>
                        <span class="auth-required">Auth Required</span>
                    </div>
                    <div class="endpoint-desc">Listar usuarios del sistema</div>
                    <div class="permissions"><strong>Permisos:</strong> manage_users</div>
                </div>

                <div class="endpoint">
                    <div class="endpoint-header">
                        <span class="method GET">GET</span>
                        <span class="endpoint-url">/api/users/profile.php</span>
                        <span class="auth-required">Auth Required</span>
                    </div>
                    <div class="endpoint-desc">Obtener perfil del usuario actual</div>
                </div>
            </div>
        </div>

        <!-- Sistema y Estadísticas -->
        <div class="section">
            <h2>📊 Sistema y Estadísticas</h2>
            <div class="endpoint-group">
                <div class="group-title">System Information</div>
                
                <div class="endpoint">
                    <div class="endpoint-header">
                        <span class="method GET">GET</span>
                        <span class="endpoint-url">/api/system/stats.php</span>
                        <span class="auth-required">Auth Required</span>
                    </div>
                    <div class="endpoint-desc">Estadísticas completas del sistema</div>
                    <div class="permissions"><strong>Permisos:</strong> view_stats</div>
                </div>

                <div class="endpoint">
                    <div class="endpoint-header">
                        <span class="method GET">GET</span>
                        <span class="endpoint-url">/api/system/health.php</span>
                    </div>
                    <div class="endpoint-desc">Estado de salud del sistema</div>
                </div>

                <div class="endpoint">
                    <div class="endpoint-header">
                        <span class="method GET">GET</span>
                        <span class="endpoint-url">/api/notifications/list.php</span>
                        <span class="auth-required">Auth Required</span>
                    </div>
                    <div class="endpoint-desc">Listar notificaciones del usuario</div>
                </div>
            </div>
        </div>

        <!-- Pruebas Rápidas -->
        <div class="quick-test">
            <h3>🧪 Pruebas Rápidas</h3>
            <div class="test-command">curl "http://192.168.4.1/api/relay/status.php"</div>
            <div class="test-command">curl "http://192.168.4.1/api/system/health.php"</div>
            <div class="test-command">curl -H "Authorization: Bearer {token}" "http://192.168.4.1/api/users/profile.php"</div>
        </div>

        <div class="footer">
            <p><?php echo getConfig('SYSTEM_COPYRIGHT'); ?> | API Documentation | <?php echo date('Y-m-d H:i:s'); ?></p>
        </div>
    </div>

    <script>
        // Auto-refresh cada 60 segundos
        setTimeout(function() {
            window.location.reload();
        }, 60000);
        
        console.log('SKYN3T API Documentation');
        console.log('Base URL:', 'http://192.168.4.1/api');
        console.log('Version:', '2.0.0');
    </script>
</body>
</html>
