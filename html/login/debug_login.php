<?php
/**
 * SKYN3T - Diagnóstico de Login
 * Archivo: /var/www/html/login/debug_login.php
 * Herramienta de diagnóstico para el sistema de login
 * 
 * @version 2.0
 * @author SKYN3T Team
 * @database skyn3t_db (MariaDB)
 * 
 * NOTA: Solo accesible en modo debug o para SuperUser
 */

// Verificar si el modo debug está habilitado
$debugMode = defined('DEBUG') && DEBUG;
$isLocalhost = in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1', 'localhost']);

if (!$debugMode && !$isLocalhost) {
    http_response_code(404);
    exit('Not Found');
}

// Inicializar sistema
require_once '/var/www/html/includes/init.php';

// Headers
header('Content-Type: text/html; charset=utf-8');
header('X-Robots-Tag: noindex, nofollow');

// Verificar permisos si hay sesión activa
$currentUser = getCurrentUser();
if ($currentUser && $currentUser['role'] !== 'SuperUser' && !$debugMode) {
    http_response_code(403);
    exit('Access Denied');
}

/**
 * Obtener información del sistema
 */
function getSystemDiagnostics() {
    $diagnostics = [
        'timestamp' => date('Y-m-d H:i:s'),
        'system' => [],
        'database' => [],
        'session' => [],
        'files' => [],
        'security' => [],
        'performance' => []
    ];
    
    // Información del sistema
    $diagnostics['system'] = [
        'skyn3t_version' => SystemConfig::SYSTEM_VERSION,
        'php_version' => PHP_VERSION,
        'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
        'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? '',
        'script_name' => $_SERVER['SCRIPT_NAME'] ?? '',
        'request_method' => $_SERVER['REQUEST_METHOD'] ?? '',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? '',
        'debug_mode' => isDebugMode(),
        'maintenance_mode' => isMaintenanceMode(),
        'timezone' => date_default_timezone_get(),
        'memory_limit' => ini_get('memory_limit'),
        'max_execution_time' => ini_get('max_execution_time'),
        'upload_max_filesize' => ini_get('upload_max_filesize')
    ];
    
    // Información de la base de datos
    try {
        $db = Database::getInstance();
        $diagnostics['database'] = [
            'connected' => $db->isConnected(),
            'host' => DatabaseConfig::DB_HOST,
            'name' => DatabaseConfig::DB_NAME,
            'charset' => DatabaseConfig::DB_CHARSET,
            'structure' => $db->checkDatabaseStructure()
        ];
        
        // Estadísticas de usuarios
        if ($db->isConnected()) {
            $userStats = $db->fetchOne("
                SELECT 
                    COUNT(*) as total_users,
                    SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) as active_users,
                    COUNT(DISTINCT role) as total_roles
                FROM usuarios
            ");
            $diagnostics['database']['user_stats'] = $userStats;
            
            // Estadísticas de sesiones
            $sessionStats = $db->fetchOne("
                SELECT 
                    COUNT(*) as total_sessions,
                    COUNT(CASE WHEN expires_at > NOW() THEN 1 END) as active_sessions,
                    COUNT(CASE WHEN expires_at <= NOW() THEN 1 END) as expired_sessions
                FROM sessions
            ");
            $diagnostics['database']['session_stats'] = $sessionStats;
        }
    } catch (Exception $e) {
        $diagnostics['database']['error'] = $e->getMessage();
    }
    
    // Información de sesión PHP
    $diagnostics['session'] = [
        'status' => session_status(),
        'id' => session_id(),
        'name' => session_name(),
        'cookie_params' => session_get_cookie_params(),
        'data' => $_SESSION ?? [],
        'gc_maxlifetime' => ini_get('session.gc_maxlifetime'),
        'use_strict_mode' => ini_get('session.use_strict_mode'),
        'cookie_httponly' => ini_get('session.cookie_httponly'),
        'cookie_secure' => ini_get('session.cookie_secure')
    ];
    
    // Verificación de archivos críticos
    $criticalFiles = [
        '/var/www/html/includes/init.php',
        '/var/www/html/includes/database.php',
        '/var/www/html/includes/auth.php',
        '/var/www/html/includes/config.php',
        '/var/www/html/includes/functions.php',
        '/var/www/html/login/login.php',
        '/var/www/html/login/check_session.php',
        '/var/www/html/login/logout.php',
        '/var/www/html/login/index_login.html'
    ];
    
    $diagnostics['files'] = [];
    foreach ($criticalFiles as $file) {
        $diagnostics['files'][$file] = [
            'exists' => file_exists($file),
            'readable' => is_readable($file),
            'writable' => is_writable($file),
            'size' => file_exists($file) ? filesize($file) : 0,
            'modified' => file_exists($file) ? date('Y-m-d H:i:s', filemtime($file)) : null
        ];
    }
    
    // Verificaciones de seguridad
    $diagnostics['security'] = [
        'https' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'headers' => [
            'x_frame_options' => $_SERVER['HTTP_X_FRAME_OPTIONS'] ?? 'Not Set',
            'x_content_type_options' => $_SERVER['HTTP_X_CONTENT_TYPE_OPTIONS'] ?? 'Not Set',
            'x_xss_protection' => $_SERVER['HTTP_X_XSS_PROTECTION'] ?? 'Not Set'
        ],
        'php_security' => [
            'display_errors' => ini_get('display_errors'),
            'expose_php' => ini_get('expose_php'),
            'allow_url_fopen' => ini_get('allow_url_fopen'),
            'allow_url_include' => ini_get('allow_url_include')
        ]
    ];
    
    // Información de rendimiento
    $diagnostics['performance'] = [
        'memory_usage' => formatBytes(memory_get_usage(true)),
        'peak_memory' => formatBytes(memory_get_peak_usage(true)),
        'execution_time' => round((microtime(true) - $_SERVER['REQUEST_TIME_FLOAT']) * 1000, 2) . 'ms',
        'included_files_count' => count(get_included_files()),
        'loaded_extensions' => get_loaded_extensions()
    ];
    
    return $diagnostics;
}

/**
 * Probar conectividad de la base de datos
 */
function testDatabaseConnectivity() {
    $tests = [];
    
    try {
        $db = Database::getInstance();
        
        // Test 1: Conexión básica
        $tests['connection'] = [
            'name' => 'Conexión Básica',
            'status' => $db->isConnected(),
            'message' => $db->isConnected() ? 'Conectado correctamente' : 'Error de conexión'
        ];
        
        // Test 2: Consulta simple
        try {
            $result = $db->fetchOne("SELECT 1 as test");
            $tests['simple_query'] = [
                'name' => 'Consulta Simple',
                'status' => $result && $result['test'] == 1,
                'message' => $result ? 'Consulta ejecutada correctamente' : 'Error en consulta'
            ];
        } catch (Exception $e) {
            $tests['simple_query'] = [
                'name' => 'Consulta Simple',
                'status' => false,
                'message' => 'Error: ' . $e->getMessage()
            ];
        }
        
        // Test 3: Verificar tabla usuarios
        try {
            $userCount = $db->fetchOne("SELECT COUNT(*) as count FROM usuarios");
            $tests['users_table'] = [
                'name' => 'Tabla Usuarios',
                'status' => $userCount !== false,
                'message' => $userCount ? "Tabla existe con {$userCount['count']} usuarios" : 'Tabla no encontrada'
            ];
        } catch (Exception $e) {
            $tests['users_table'] = [
                'name' => 'Tabla Usuarios',
                'status' => false,
                'message' => 'Error: ' . $e->getMessage()
            ];
        }
        
        // Test 4: Verificar tabla sessions
        try {
            $sessionCount = $db->fetchOne("SELECT COUNT(*) as count FROM sessions");
            $tests['sessions_table'] = [
                'name' => 'Tabla Sessions',
                'status' => $sessionCount !== false,
                'message' => $sessionCount ? "Tabla existe con {$sessionCount['count']} sesiones" : 'Tabla no encontrada'
            ];
        } catch (Exception $e) {
            $tests['sessions_table'] = [
                'name' => 'Tabla Sessions',
                'status' => false,
                'message' => 'Error: ' . $e->getMessage()
            ];
        }
        
    } catch (Exception $e) {
        $tests['connection'] = [
            'name' => 'Conexión Básica',
            'status' => false,
            'message' => 'Error crítico: ' . $e->getMessage()
        ];
    }
    
    return $tests;
}

/**
 * Obtener logs recientes del sistema
 */
function getRecentLogs() {
    $logs = [];
    
    try {
        $db = Database::getInstance();
        
        if ($db->isConnected()) {
            // Logs de acceso recientes
            $accessLogs = $db->fetchAll("
                SELECT username, action, status, ip_address, created_at 
                FROM access_log 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
                ORDER BY created_at DESC 
                LIMIT 20
            ");
            
            $logs['access'] = $accessLogs ?: [];
            
            // Intentos de login fallidos
            $failedLogins = $db->fetchAll("
                SELECT username, ip_address, created_at 
                FROM access_log 
                WHERE action = 'failed_login' 
                AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                ORDER BY created_at DESC 
                LIMIT 10
            ");
            
            $logs['failed_logins'] = $failedLogins ?: [];
        }
    } catch (Exception $e) {
        $logs['error'] = $e->getMessage();
    }
    
    return $logs;
}

// Obtener información de diagnóstico
$diagnostics = getSystemDiagnostics();
$dbTests = testDatabaseConnectivity();
$recentLogs = getRecentLogs();

// Registrar acceso al diagnóstico
writeLog('info', 'Acceso a diagnóstico de login', [
    'user' => $currentUser['username'] ?? 'anonymous',
    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
]);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SKYN3T - Diagnóstico de Login</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Courier New', monospace;
            background: #000;
            color: #00ff00;
            padding: 20px;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #00ff00;
            padding-bottom: 20px;
        }
        
        .header h1 {
            font-size: 28px;
            text-shadow: 0 0 10px #00ff00;
        }
        
        .section {
            margin-bottom: 30px;
            border: 1px solid #00ff00;
            border-radius: 5px;
            padding: 20px;
            background: rgba(0, 255, 0, 0.05);
        }
        
        .section h2 {
            color: #ffff00;
            margin-bottom: 15px;
            font-size: 20px;
        }
        
        .status-ok {
            color: #00ff00;
        }
        
        .status-error {
            color: #ff0000;
        }
        
        .status-warning {
            color: #ffff00;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }
        
        .info-item {
            background: rgba(0, 255, 0, 0.1);
            padding: 10px;
            border-radius: 3px;
            border-left: 3px solid #00ff00;
        }
        
        .test-result {
            margin: 10px 0;
            padding: 8px;
            border-radius: 3px;
        }
        
        .test-pass {
            background: rgba(0, 255, 0, 0.2);
            border-left: 3px solid #00ff00;
        }
        
        .test-fail {
            background: rgba(255, 0, 0, 0.2);
            border-left: 3px solid #ff0000;
        }
        
        .log-entry {
            margin: 5px 0;
            padding: 5px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 3px;
            font-size: 12px;
        }
        
        .actions {
            margin-top: 30px;
            text-align: center;
        }
        
        .btn {
            background: #00ff00;
            color: #000;
            padding: 10px 20px;
            text-decoration: none;
            margin: 0 10px;
            border-radius: 3px;
            font-weight: bold;
        }
        
        .btn:hover {
            background: #00cc00;
        }
        
        pre {
            background: rgba(255, 255, 255, 0.1);
            padding: 10px;
            border-radius: 3px;
            overflow-x: auto;
            font-size: 12px;
        }
        
        .timestamp {
            color: #888;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔧 SKYN3T - DIAGNÓSTICO DE LOGIN</h1>
            <div class="timestamp">
                Generado: <?= $diagnostics['timestamp'] ?> | 
                Usuario: <?= $currentUser['username'] ?? 'Anonymous' ?> | 
                Versión: <?= $diagnostics['system']['skyn3t_version'] ?>
            </div>
        </div>

        <!-- Información del Sistema -->
        <div class="section">
            <h2>📊 Información del Sistema</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>SKYN3T:</strong> v<?= $diagnostics['system']['skyn3t_version'] ?>
                </div>
                <div class="info-item">
                    <strong>PHP:</strong> <?= $diagnostics['system']['php_version'] ?>
                </div>
                <div class="info-item">
                    <strong>Servidor:</strong> <?= $diagnostics['system']['server_software'] ?>
                </div>
                <div class="info-item">
                    <strong>Modo Debug:</strong> 
                    <span class="<?= $diagnostics['system']['debug_mode'] ? 'status-warning' : 'status-ok' ?>">
                        <?= $diagnostics['system']['debug_mode'] ? 'ACTIVADO' : 'DESACTIVADO' ?>
                    </span>
                </div>
                <div class="info-item">
                    <strong>Memoria:</strong> <?= $diagnostics['performance']['memory_usage'] ?>
                </div>
                <div class="info-item">
                    <strong>Tiempo de Ejecución:</strong> <?= $diagnostics['performance']['execution_time'] ?>
                </div>
            </div>
        </div>

        <!-- Test de Base de Datos -->
        <div class="section">
            <h2>🗄️ Pruebas de Base de Datos</h2>
            <?php foreach ($dbTests as $test): ?>
                <div class="test-result <?= $test['status'] ? 'test-pass' : 'test-fail' ?>">
                    <strong><?= $test['name'] ?>:</strong> 
                    <span class="<?= $test['status'] ? 'status-ok' : 'status-error' ?>">
                        <?= $test['status'] ? '✓ PASS' : '✗ FAIL' ?>
                    </span>
                    - <?= $test['message'] ?>
                </div>
            <?php endforeach; ?>
            
            <?php if (isset($diagnostics['database']['structure'])): ?>
                <h3 style="color: #ffff00; margin-top: 20px;">Estructura de Base de Datos:</h3>
                <pre><?= json_encode($diagnostics['database']['structure'], JSON_PRETTY_PRINT) ?></pre>
            <?php endif; ?>
        </div>

        <!-- Información de Sesión -->
        <div class="section">
            <h2>🔐 Estado de Sesión</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Estado PHP:</strong> 
                    <?php
                    $sessionStatus = [
                        PHP_SESSION_DISABLED => 'DESHABILITADA',
                        PHP_SESSION_NONE => 'SIN SESIÓN',
                        PHP_SESSION_ACTIVE => 'ACTIVA'
                    ];
                    echo $sessionStatus[$diagnostics['session']['status']] ?? 'DESCONOCIDO';
                    ?>
                </div>
                <div class="info-item">
                    <strong>ID de Sesión:</strong> <?= $diagnostics['session']['id'] ?: 'N/A' ?>
                </div>
                <div class="info-item">
                    <strong>Cookie Segura:</strong> 
                    <span class="<?= $diagnostics['session']['cookie_secure'] ? 'status-ok' : 'status-warning' ?>">
                        <?= $diagnostics['session']['cookie_secure'] ? 'SÍ' : 'NO' ?>
                    </span>
                </div>
                <div class="info-item">
                    <strong>HTTP Only:</strong> 
                    <span class="<?= $diagnostics['session']['cookie_httponly'] ? 'status-ok' : 'status-warning' ?>">
                        <?= $diagnostics['session']['cookie_httponly'] ? 'SÍ' : 'NO' ?>
                    </span>
                </div>
            </div>
            
            <?php if (!empty($diagnostics['session']['data'])): ?>
                <h3 style="color: #ffff00; margin-top: 15px;">Datos de Sesión:</h3>
                <pre><?= json_encode($diagnostics['session']['data'], JSON_PRETTY_PRINT) ?></pre>
            <?php endif; ?>
        </div>

        <!-- Archivos del Sistema -->
        <div class="section">
            <h2>📁 Verificación de Archivos</h2>
            <?php foreach ($diagnostics['files'] as $file => $info): ?>
                <div class="test-result <?= $info['exists'] && $info['readable'] ? 'test-pass' : 'test-fail' ?>">
                    <strong><?= basename($file) ?>:</strong>
                    <?php if ($info['exists']): ?>
                        <span class="status-ok">✓ EXISTE</span>
                        (<?= formatBytes($info['size']) ?>, modificado: <?= $info['modified'] ?>)
                        <?php if (!$info['readable']): ?>
                            <span class="status-error">- NO LEGIBLE</span>
                        <?php endif; ?>
                    <?php else: ?>
                        <span class="status-error">✗ NO ENCONTRADO</span>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>

        <!-- Logs Recientes -->
        <div class="section">
            <h2>📋 Logs Recientes (Última Hora)</h2>
            
            <?php if (!empty($recentLogs['access'])): ?>
                <h3 style="color: #ffff00;">Accesos:</h3>
                <?php foreach ($recentLogs['access'] as $log): ?>
                    <div class="log-entry">
                        <span class="timestamp"><?= $log['created_at'] ?></span> | 
                        <strong><?= $log['username'] ?></strong> | 
                        <?= $log['action'] ?> | 
                        <span class="<?= $log['status'] === 'success' ? 'status-ok' : 'status-error' ?>">
                            <?= strtoupper($log['status']) ?>
                        </span> | 
                        IP: <?= $log['ip_address'] ?>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
            
            <?php if (!empty($recentLogs['failed_logins'])): ?>
                <h3 style="color: #ff0000; margin-top: 15px;">Intentos Fallidos (Últimas 24h):</h3>
                <?php foreach ($recentLogs['failed_logins'] as $log): ?>
                    <div class="log-entry">
                        <span class="timestamp"><?= $log['created_at'] ?></span> | 
                        <strong><?= $log['username'] ?></strong> | 
                        IP: <?= $log['ip_address'] ?>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <!-- Seguridad -->
        <div class="section">
            <h2>🛡️ Configuración de Seguridad</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>HTTPS:</strong> 
                    <span class="<?= $diagnostics['security']['https'] ? 'status-ok' : 'status-warning' ?>">
                        <?= $diagnostics['security']['https'] ? 'ACTIVADO' : 'NO DETECTADO' ?>
                    </span>
                </div>
                <div class="info-item">
                    <strong>Display Errors:</strong> 
                    <span class="<?= !$diagnostics['security']['php_security']['display_errors'] ? 'status-ok' : 'status-warning' ?>">
                        <?= $diagnostics['security']['php_security']['display_errors'] ? 'ACTIVADO' : 'DESACTIVADO' ?>
                    </span>
                </div>
                <div class="info-item">
                    <strong>Expose PHP:</strong> 
                    <span class="<?= !$diagnostics['security']['php_security']['expose_php'] ? 'status-ok' : 'status-warning' ?>">
                        <?= $diagnostics['security']['php_security']['expose_php'] ? 'ACTIVADO' : 'DESACTIVADO' ?>
                    </span>
                </div>
            </div>
        </div>

        <!-- Acciones -->
        <div class="actions">
            <a href="/login/index_login.html" class="btn">🔐 Ir al Login</a>
            <a href="/dashboard/index.php" class="btn">🏠 Dashboard</a>
            <a href="?refresh=1" class="btn">🔄 Actualizar</a>
            <?php if ($currentUser): ?>
                <a href="/login/logout.php" class="btn">🚪 Logout</a>
            <?php endif; ?>
        </div>
    </div>

    <script>
        // Auto-refresh cada 30 segundos si se especifica
        if (window.location.search.includes('auto=true')) {
            setTimeout(() => {
                window.location.reload();
            }, 30000);
        }
        
        console.log('SKYN3T Login Diagnostics v2.0');
        console.log('Diagnóstico generado en:', '<?= $diagnostics['timestamp'] ?>');
    </script>
</body>
</html>