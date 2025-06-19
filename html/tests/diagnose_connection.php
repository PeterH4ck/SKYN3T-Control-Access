<?php
// Archivo: /var/www/html/diagnose_connection.php
// Script de diagnóstico para problemas de conexión

header('Content-Type: text/html; charset=UTF-8');

// Función para verificar extensiones PHP
function checkPHPExtensions() {
    $required = ['pdo', 'pdo_mysql', 'json', 'session'];
    $missing = [];
    
    foreach ($required as $ext) {
        if (!extension_loaded($ext)) {
            $missing[] = $ext;
        }
    }
    
    return $missing;
}

// Función para verificar conexión a base de datos
function testDatabaseConnection() {
    try {
        require_once 'includes/database.php';
        $pdo = getDBConnection();
        
        if ($pdo) {
            // Intentar una consulta simple
            $stmt = $pdo->query("SELECT 1");
            return ['success' => true, 'message' => 'Conexión exitosa'];
        } else {
            return ['success' => false, 'message' => 'No se pudo establecer conexión'];
        }
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

// Función para verificar permisos de archivos
function checkFilePermissions() {
    $paths = [
        '/var/www/html/includes' => 'Directorio includes',
        '/var/www/html/includes/database.php' => 'Archivo database.php',
        '/var/www/html/login' => 'Directorio login',
        '/var/www/html/api' => 'Directorio API'
    ];
    
    $issues = [];
    
    foreach ($paths as $path => $desc) {
        if (!file_exists($path)) {
            $issues[] = "$desc no existe";
        } elseif (!is_readable($path)) {
            $issues[] = "$desc no es legible";
        }
    }
    
    return $issues;
}

// Función para verificar configuración de sesiones
function checkSessionConfig() {
    $config = [
        'session.save_path' => session_save_path(),
        'session.save_handler' => ini_get('session.save_handler'),
        'session.gc_maxlifetime' => ini_get('session.gc_maxlifetime'),
        'session.cookie_lifetime' => ini_get('session.cookie_lifetime')
    ];
    
    $writable = is_writable(session_save_path());
    
    return ['config' => $config, 'writable' => $writable];
}

// Iniciar diagnóstico
$diagnostics = [
    'timestamp' => date('Y-m-d H:i:s'),
    'server' => [
        'software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
        'php_version' => PHP_VERSION,
        'os' => PHP_OS
    ],
    'client' => [
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
        'is_mobile' => preg_match('/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i', $_SERVER['HTTP_USER_AGENT'] ?? '')
    ]
];

// Verificar extensiones PHP
$missing_extensions = checkPHPExtensions();
$diagnostics['php_extensions'] = [
    'status' => empty($missing_extensions) ? 'OK' : 'ERROR',
    'missing' => $missing_extensions
];

// Verificar conexión a base de datos
$db_test = testDatabaseConnection();
$diagnostics['database'] = $db_test;

// Verificar permisos de archivos
$permission_issues = checkFilePermissions();
$diagnostics['file_permissions'] = [
    'status' => empty($permission_issues) ? 'OK' : 'WARNING',
    'issues' => $permission_issues
];

// Verificar configuración de sesiones
$session_info = checkSessionConfig();
$diagnostics['sessions'] = $session_info;

// Verificar CORS headers
$diagnostics['cors'] = [
    'enabled' => function_exists('getallheaders'),
    'headers_sent' => headers_sent()
];

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Diagnóstico de Conexión - Sistema de Control de Acceso</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .section {
            margin: 20px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .status-ok {
            color: #27ae60;
            font-weight: bold;
        }
        .status-error {
            color: #e74c3c;
            font-weight: bold;
        }
        .status-warning {
            color: #f39c12;
            font-weight: bold;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #3498db;
            color: white;
        }
        .code {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }
        .test-button {
            background: #3498db;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        .test-button:hover {
            background: #2980b9;
        }
        .mobile-info {
            background: #e8f4f8;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Diagnóstico de Conexión</h1>
        
        <?php if ($diagnostics['client']['is_mobile']): ?>
        <div class="mobile-info">
            📱 <strong>Dispositivo móvil detectado</strong> - Verificando compatibilidad móvil...
        </div>
        <?php endif; ?>
        
        <div class="section">
            <h2>Información del Sistema</h2>
            <table>
                <tr>
                    <th>Componente</th>
                    <th>Valor</th>
                </tr>
                <tr>
                    <td>Servidor Web</td>
                    <td><?php echo htmlspecialchars($diagnostics['server']['software']); ?></td>
                </tr>
                <tr>
                    <td>Versión PHP</td>
                    <td><?php echo $diagnostics['server']['php_version']; ?></td>
                </tr>
                <tr>
                    <td>Sistema Operativo</td>
                    <td><?php echo $diagnostics['server']['os']; ?></td>
                </tr>
                <tr>
                    <td>IP Cliente</td>
                    <td><?php echo htmlspecialchars($diagnostics['client']['ip']); ?></td>
                </tr>
                <tr>
                    <td>Navegador</td>
                    <td><?php echo htmlspecialchars($diagnostics['client']['user_agent']); ?></td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Extensiones PHP</h2>
            <?php if ($diagnostics['php_extensions']['status'] === 'OK'): ?>
                <p class="status-ok">✓ Todas las extensiones requeridas están instaladas</p>
            <?php else: ?>
                <p class="status-error">✗ Extensiones faltantes: <?php echo implode(', ', $diagnostics['php_extensions']['missing']); ?></p>
            <?php endif; ?>
        </div>
        
        <div class="section">
            <h2>Conexión a Base de Datos</h2>
            <?php if ($diagnostics['database']['success']): ?>
                <p class="status-ok">✓ <?php echo $diagnostics['database']['message']; ?></p>
            <?php else: ?>
                <p class="status-error">✗ <?php echo htmlspecialchars($diagnostics['database']['message']); ?></p>
                <p>Verifique la configuración en <code>/var/www/html/includes/database.php</code></p>
            <?php endif; ?>
        </div>
        
        <div class="section">
            <h2>Permisos de Archivos</h2>
            <?php if ($diagnostics['file_permissions']['status'] === 'OK'): ?>
                <p class="status-ok">✓ Todos los archivos tienen permisos correctos</p>
            <?php else: ?>
                <p class="status-warning">⚠ Problemas detectados:</p>
                <ul>
                    <?php foreach ($diagnostics['file_permissions']['issues'] as $issue): ?>
                        <li><?php echo htmlspecialchars($issue); ?></li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
        
        <div class="section">
            <h2>Configuración de Sesiones</h2>
            <table>
                <tr>
                    <th>Parámetro</th>
                    <th>Valor</th>
                </tr>
                <?php foreach ($diagnostics['sessions']['config'] as $key => $value): ?>
                <tr>
                    <td><?php echo $key; ?></td>
                    <td><?php echo htmlspecialchars($value); ?></td>
                </tr>
                <?php endforeach; ?>
            </table>
            <?php if ($diagnostics['sessions']['writable']): ?>
                <p class="status-ok">✓ Directorio de sesiones es escribible</p>
            <?php else: ?>
                <p class="status-error">✗ El directorio de sesiones NO es escribible</p>
            <?php endif; ?>
        </div>
        
        <div class="section">
            <h2>Test de API</h2>
            <p>Haga clic en el botón para probar la conexión con la API de login:</p>
            <button class="test-button" onclick="testAPI()">Probar API de Login</button>
            <div id="api-result" style="margin-top: 10px;"></div>
        </div>
        
        <div class="section">
            <h2>Soluciones Comunes</h2>
            <ul>
                <li><strong>Error de conexión en móvil:</strong> Verifique que el dispositivo esté en la misma red que el servidor</li>
                <li><strong>Error de base de datos:</strong> Ejecute <code>sudo bash setup_complete_database.sh</code></li>
                <li><strong>Error de permisos:</strong> Ejecute <code>sudo chown -R www-data:www-data /var/www/html/</code></li>
                <li><strong>Error de sesiones:</strong> Ejecute <code>sudo chmod 777 /var/lib/php/sessions/</code></li>
            </ul>
        </div>
    </div>
    
    <script>
        function testAPI() {
            const resultDiv = document.getElementById('api-result');
            resultDiv.innerHTML = '<p>Probando conexión...</p>';
            
            fetch('/login/login.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: 'test',
                    password: 'test'
                })
            })
            .then(response => response.json())
            .then(data => {
                resultDiv.innerHTML = '<div class="code">' + JSON.stringify(data, null, 2) + '</div>';
            })
            .catch(error => {
                resultDiv.innerHTML = '<p class="status-error">Error: ' + error.message + '</p>';
            });
        }
    </script>
</body>
</html>
