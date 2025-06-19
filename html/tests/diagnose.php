<?php
/**
 * SKYN3T Deep Diagnostics Tool
 * Herramienta de diagnóstico profundo para identificar problemas
 * Guardar como: /var/www/html/diagnose.php
 */

// Desactivar cache
header('Cache-Control: no-cache, must-revalidate');
header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');

// Configurar reporte de errores completo
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
ini_set('log_errors', 1);

?>
<!DOCTYPE html>
<html>
<head>
    <title>SKYN3T - Diagnóstico Profundo</title>
    <style>
        body {
            font-family: monospace;
            background: #000;
            color: #0f0;
            padding: 20px;
            line-height: 1.6;
        }
        .section {
            border: 1px solid #0f0;
            padding: 15px;
            margin: 20px 0;
            background: rgba(0,255,0,0.05);
        }
        .error {
            color: #f00;
            font-weight: bold;
        }
        .success {
            color: #0f0;
            font-weight: bold;
        }
        .warning {
            color: #ff0;
            font-weight: bold;
        }
        .code {
            background: #111;
            padding: 10px;
            border-left: 3px solid #0f0;
            margin: 10px 0;
            overflow-x: auto;
        }
        h2 {
            color: #ff0;
            border-bottom: 2px solid #ff0;
            padding-bottom: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        td, th {
            border: 1px solid #0f0;
            padding: 8px;
            text-align: left;
        }
        th {
            background: rgba(0,255,0,0.2);
        }
        .fix-btn {
            background: #0f0;
            color: #000;
            padding: 10px 20px;
            border: none;
            cursor: pointer;
            font-weight: bold;
            margin: 10px 0;
        }
        .fix-btn:hover {
            background: #0a0;
        }
    </style>
</head>
<body>

<h1>🔍 SKYN3T DEEP DIAGNOSTICS v2.0</h1>
<p>Fecha: <?= date('Y-m-d H:i:s') ?></p>

<?php

$errors = [];
$warnings = [];
$fixes_available = [];

// =============================================================================
// 1. INFORMACIÓN DEL SISTEMA
// =============================================================================
echo '<div class="section">';
echo '<h2>1. Información del Sistema</h2>';

$system_info = [
    'PHP Version' => PHP_VERSION,
    'Server Software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
    'Document Root' => $_SERVER['DOCUMENT_ROOT'] ?? 'Unknown',
    'Script Path' => __FILE__,
    'Request URI' => $_SERVER['REQUEST_URI'] ?? 'Unknown',
    'Memory Limit' => ini_get('memory_limit'),
    'Max Execution Time' => ini_get('max_execution_time'),
    'Display Errors' => ini_get('display_errors') ? 'On' : 'Off',
    'Error Reporting' => error_reporting(),
];

echo '<table>';
foreach ($system_info as $key => $value) {
    echo "<tr><td><strong>$key:</strong></td><td>$value</td></tr>";
}
echo '</table>';
echo '</div>';

// =============================================================================
// 2. VERIFICAR LOGS DE ERROR
// =============================================================================
echo '<div class="section">';
echo '<h2>2. Logs de Error</h2>';

// Buscar archivo de error log
$error_logs = [
    '/var/log/apache2/error.log',
    '/var/log/nginx/error.log',
    '/var/log/php/error.log',
    '/var/www/html/logs/error.log',
    ini_get('error_log')
];

$log_found = false;
foreach ($error_logs as $log_file) {
    if ($log_file && file_exists($log_file) && is_readable($log_file)) {
        echo "<p class='success'>Log encontrado: $log_file</p>";
        
        // Leer últimas líneas
        $lines = shell_exec("tail -n 20 '$log_file' 2>&1");
        echo '<div class="code">';
        echo '<strong>Últimas 20 líneas:</strong><br>';
        echo nl2br(htmlspecialchars($lines));
        echo '</div>';
        $log_found = true;
        break;
    }
}

if (!$log_found) {
    echo '<p class="warning">No se encontraron logs accesibles</p>';
    
    // Crear archivo de log si no existe
    $custom_log = '/var/www/html/logs/php_errors.log';
    if (!file_exists(dirname($custom_log))) {
        mkdir(dirname($custom_log), 0777, true);
    }
    touch($custom_log);
    chmod($custom_log, 0666);
    ini_set('error_log', $custom_log);
    echo "<p>Creado nuevo archivo de log: $custom_log</p>";
}

echo '</div>';

// =============================================================================
// 3. VERIFICAR SINTAXIS DE ARCHIVOS PHP CRÍTICOS
// =============================================================================
echo '<div class="section">';
echo '<h2>3. Verificación de Sintaxis PHP</h2>';

$critical_files = [
    '/var/www/html/includes/init.php',
    '/var/www/html/includes/database.php',
    '/var/www/html/includes/config.php',
    '/var/www/html/includes/auth.php',
    '/var/www/html/includes/functions.php',
    '/var/www/html/login/login.php',
    '/var/www/html/login/check_session.php',
    '/var/www/html/login/logout.php',
];

foreach ($critical_files as $file) {
    if (file_exists($file)) {
        // Verificar sintaxis
        $output = shell_exec("php -l '$file' 2>&1");
        
        if (strpos($output, 'No syntax errors detected') !== false) {
            echo "<p class='success'>✓ $file - Sintaxis OK</p>";
        } else {
            echo "<p class='error'>✗ $file - Error de sintaxis:</p>";
            echo "<div class='code'>" . nl2br(htmlspecialchars($output)) . "</div>";
            $errors[] = "Syntax error in $file";
        }
        
        // Verificar permisos
        if (!is_readable($file)) {
            echo "<p class='warning'>⚠ $file - No es legible</p>";
            $warnings[] = "$file is not readable";
        }
    } else {
        echo "<p class='error'>✗ $file - NO EXISTE</p>";
        $errors[] = "$file does not exist";
    }
}

echo '</div>';

// =============================================================================
// 4. PROBAR INCLUDES PASO A PASO
// =============================================================================
echo '<div class="section">';
echo '<h2>4. Prueba de Includes Paso a Paso</h2>';

// Probar cada include individualmente
$includes_to_test = [
    'config.php' => '/var/www/html/includes/config.php',
    'database.php' => '/var/www/html/includes/database.php',
    'functions.php' => '/var/www/html/includes/functions.php',
    'auth.php' => '/var/www/html/includes/auth.php',
];

foreach ($includes_to_test as $name => $path) {
    echo "<p><strong>Probando $name...</strong></p>";
    
    try {
        ob_start();
        $error_before = error_get_last();
        
        // Suprimir warnings para capturarlos
        @include_once $path;
        
        $error_after = error_get_last();
        $output = ob_get_clean();
        
        if ($error_after && $error_after !== $error_before) {
            echo "<p class='error'>Error al incluir $name:</p>";
            echo "<div class='code'>" . htmlspecialchars($error_after['message']) . "</div>";
            $errors[] = "Include error in $name";
        } else {
            echo "<p class='success'>✓ $name incluido correctamente</p>";
        }
        
        if ($output) {
            echo "<p class='warning'>Output inesperado:</p>";
            echo "<div class='code'>" . htmlspecialchars($output) . "</div>";
        }
        
    } catch (Exception $e) {
        echo "<p class='error'>Excepción al incluir $name:</p>";
        echo "<div class='code'>" . htmlspecialchars($e->getMessage()) . "</div>";
        $errors[] = "Exception in $name: " . $e->getMessage();
    }
}

echo '</div>';

// =============================================================================
// 5. VERIFICAR BASE DE DATOS DETALLADA
// =============================================================================
echo '<div class="section">';
echo '<h2>5. Verificación Detallada de Base de Datos</h2>';

// Intentar conexión directa
try {
    $pdo = new PDO(
        "mysql:host=localhost;dbname=skyn3t_db;charset=utf8mb4",
        "admin",
        "admin",
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
    echo "<p class='success'>✓ Conexión directa a MySQL exitosa</p>";
    
    // Verificar estructura de tabla usuarios
    $stmt = $pdo->query("DESCRIBE usuarios");
    $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo "<p><strong>Estructura de tabla 'usuarios':</strong></p>";
    echo "<table>";
    echo "<tr><th>Campo</th><th>Tipo</th><th>Null</th><th>Key</th><th>Default</th></tr>";
    
    $required_fields = ['id', 'username', 'password', 'name', 'email', 'role', 'active', 'privileges'];
    $missing_fields = [];
    $existing_fields = [];
    
    foreach ($columns as $col) {
        echo "<tr>";
        echo "<td>{$col['Field']}</td>";
        echo "<td>{$col['Type']}</td>";
        echo "<td>{$col['Null']}</td>";
        echo "<td>{$col['Key']}</td>";
        echo "<td>{$col['Default']}</td>";
        echo "</tr>";
        $existing_fields[] = $col['Field'];
    }
    echo "</table>";
    
    // Verificar campos faltantes
    foreach ($required_fields as $field) {
        if (!in_array($field, $existing_fields)) {
            $missing_fields[] = $field;
            echo "<p class='error'>❌ Campo faltante: $field</p>";
        }
    }
    
    if (!empty($missing_fields)) {
        $fixes_available[] = 'add_missing_fields';
    }
    
    // Verificar usuarios
    $stmt = $pdo->query("SELECT id, username, role, active FROM usuarios");
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo "<p><strong>Usuarios en la base de datos:</strong></p>";
    echo "<table>";
    echo "<tr><th>ID</th><th>Username</th><th>Role</th><th>Active</th></tr>";
    foreach ($users as $user) {
        echo "<tr>";
        echo "<td>{$user['id']}</td>";
        echo "<td>{$user['username']}</td>";
        echo "<td>{$user['role']}</td>";
        echo "<td>" . ($user['active'] ? 'Sí' : 'No') . "</td>";
        echo "</tr>";
    }
    echo "</table>";
    
    // Verificar tablas faltantes
    $stmt = $pdo->query("SHOW TABLES");
    $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
    
    $required_tables = ['usuarios', 'sessions', 'access_log', 'devices', 'notifications', 'relay_control', 'system_settings', 'system_logs'];
    $missing_tables = array_diff($required_tables, $tables);
    
    if (!empty($missing_tables)) {
        echo "<p class='error'>Tablas faltantes: " . implode(', ', $missing_tables) . "</p>";
        $fixes_available[] = 'create_missing_tables';
    }
    
} catch (PDOException $e) {
    echo "<p class='error'>Error de conexión MySQL: " . htmlspecialchars($e->getMessage()) . "</p>";
    $errors[] = "MySQL connection error: " . $e->getMessage();
}

echo '</div>';

// =============================================================================
// 6. ANÁLISIS DE PROBLEMA DE LOGIN
// =============================================================================
echo '<div class="section">';
echo '<h2>6. Análisis Específico del Login</h2>';

// Verificar archivo index_login.html
$login_file = '/var/www/html/login/index_login.html';
if (file_exists($login_file)) {
    echo "<p class='success'>✓ Archivo login existe: index_login.html</p>";
    
    // Verificar que apunta al archivo correcto
    $content = file_get_contents($login_file);
    if (strpos($content, 'login.php') !== false) {
        echo "<p class='success'>✓ index_login.html apunta a login.php</p>";
    } else {
        echo "<p class='error'>❌ index_login.html no apunta a login.php</p>";
    }
    
    // Verificar rutas en el HTML
    preg_match_all('/(?:src|href|action)=["\']([^"\']+)["\']/', $content, $matches);
    echo "<p><strong>Rutas encontradas en index_login.html:</strong></p>";
    echo "<div class='code'>";
    foreach (array_unique($matches[1]) as $path) {
        echo htmlspecialchars($path) . "<br>";
    }
    echo "</div>";
} else {
    echo "<p class='error'>❌ No existe index_login.html</p>";
    $errors[] = "index_login.html not found";
}

// Verificar .htaccess
$htaccess_file = '/var/www/html/.htaccess';
if (file_exists($htaccess_file)) {
    echo "<p class='warning'>⚠ Existe .htaccess - puede estar causando redirecciones</p>";
    $htaccess_content = file_get_contents($htaccess_file);
    echo "<div class='code'>" . nl2br(htmlspecialchars($htaccess_content)) . "</div>";
}

echo '</div>';

// =============================================================================
// 7. TRACE DEL ERROR 500
// =============================================================================
echo '<div class="section">';
echo '<h2>7. Rastreo del Error 500</h2>';

// Crear archivo de prueba mínimo
$test_login = '/var/www/html/test_login_minimal.php';
$test_content = '<?php
error_reporting(E_ALL);
ini_set("display_errors", 1);

echo "<h1>Test Login Minimal</h1>";
echo "<p>PHP Version: " . PHP_VERSION . "</p>";

// Test 1: Include config
echo "<h2>Test 1: Include config.php</h2>";
if (file_exists("/var/www/html/includes/config.php")) {
    try {
        require_once "/var/www/html/includes/config.php";
        echo "<p style=\"color:green\">✓ config.php loaded</p>";
    } catch (Exception $e) {
        echo "<p style=\"color:red\">✗ Error: " . $e->getMessage() . "</p>";
    }
} else {
    echo "<p style=\"color:red\">✗ config.php not found</p>";
}

// Test 2: Include database
echo "<h2>Test 2: Include database.php</h2>";
if (file_exists("/var/www/html/includes/database.php")) {
    try {
        require_once "/var/www/html/includes/database.php";
        echo "<p style=\"color:green\">✓ database.php loaded</p>";
        
        // Test connection
        $db = Database::getInstance();
        if ($db->isConnected()) {
            echo "<p style=\"color:green\">✓ Database connected</p>";
        } else {
            echo "<p style=\"color:red\">✗ Database not connected</p>";
        }
    } catch (Exception $e) {
        echo "<p style=\"color:red\">✗ Error: " . $e->getMessage() . "</p>";
    }
} else {
    echo "<p style=\"color:red\">✗ database.php not found</p>";
}

// Test 3: Full init
echo "<h2>Test 3: Include init.php</h2>";
if (file_exists("/var/www/html/includes/init.php")) {
    try {
        ob_start();
        require_once "/var/www/html/includes/init.php";
        $output = ob_get_clean();
        echo "<p style=\"color:green\">✓ init.php loaded</p>";
        if ($output) {
            echo "<p>Output: " . htmlspecialchars($output) . "</p>";
        }
    } catch (Exception $e) {
        echo "<p style=\"color:red\">✗ Error: " . $e->getMessage() . "</p>";
    }
} else {
    echo "<p style=\"color:red\">✗ init.php not found</p>";
}
?>';

file_put_contents($test_login, $test_content);
chmod($test_login, 0644);

echo "<p>Creado archivo de prueba: <a href='/test_login_minimal.php' target='_blank'>test_login_minimal.php</a></p>";

echo '</div>';

// =============================================================================
// 8. CORRECCIONES AUTOMÁTICAS DISPONIBLES
// =============================================================================
if (!empty($fixes_available)) {
    echo '<div class="section">';
    echo '<h2>8. Correcciones Automáticas Disponibles</h2>';
    
    foreach ($fixes_available as $fix) {
        switch ($fix) {
            case 'add_missing_fields':
                echo '<form method="post" action="diagnose.php">';
                echo '<input type="hidden" name="fix" value="add_missing_fields">';
                echo '<p>Se detectaron campos faltantes en la tabla usuarios.</p>';
                echo '<button type="submit" class="fix-btn">🔧 Agregar campos faltantes</button>';
                echo '</form>';
                break;
                
            case 'create_missing_tables':
                echo '<form method="post" action="diagnose.php">';
                echo '<input type="hidden" name="fix" value="create_missing_tables">';
                echo '<p>Se detectaron tablas faltantes en la base de datos.</p>';
                echo '<button type="submit" class="fix-btn">🔧 Crear tablas faltantes</button>';
                echo '</form>';
                break;
        }
    }
    
    echo '</div>';
}

// =============================================================================
// 9. RESUMEN Y RECOMENDACIONES
// =============================================================================
echo '<div class="section">';
echo '<h2>9. Resumen y Recomendaciones</h2>';

echo "<p><strong>Errores encontrados:</strong> " . count($errors) . "</p>";
echo "<p><strong>Advertencias:</strong> " . count($warnings) . "</p>";

if (!empty($errors)) {
    echo "<h3 class='error'>Errores que deben corregirse:</h3>";
    echo "<ul>";
    foreach ($errors as $error) {
        echo "<li>" . htmlspecialchars($error) . "</li>";
    }
    echo "</ul>";
}

if (!empty($warnings)) {
    echo "<h3 class='warning'>Advertencias:</h3>";
    echo "<ul>";
    foreach ($warnings as $warning) {
        echo "<li>" . htmlspecialchars($warning) . "</li>";
    }
    echo "</ul>";
}

echo "<h3>Acciones recomendadas:</h3>";
echo "<ol>";
echo "<li>Revisar el archivo de prueba: <a href='/test_login_minimal.php' target='_blank'>test_login_minimal.php</a></li>";
echo "<li>Verificar los logs de error de Apache/PHP</li>";
echo "<li>Asegurarse de que todos los campos requeridos existen en la base de datos</li>";
echo "<li>Verificar que no hay conflictos en archivos .htaccess</li>";
echo "</ol>";

echo '</div>';

// =============================================================================
// PROCESAR CORRECCIONES SI SE SOLICITARON
// =============================================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['fix'])) {
    echo '<div class="section">';
    echo '<h2>Aplicando Corrección...</h2>';
    
    try {
        $pdo = new PDO(
            "mysql:host=localhost;dbname=skyn3t_db;charset=utf8mb4",
            "admin",
            "admin",
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
        );
        
        switch ($_POST['fix']) {
            case 'add_missing_fields':
                // Agregar campo privileges si no existe
                $pdo->exec("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS privileges JSON DEFAULT NULL");
                echo "<p class='success'>✓ Campo 'privileges' agregado</p>";
                
                // Agregar campo active si no existe
                $pdo->exec("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE");
                echo "<p class='success'>✓ Campo 'active' agregado</p>";
                
                // Agregar campo name si no existe
                $pdo->exec("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS name VARCHAR(100) DEFAULT NULL");
                echo "<p class='success'>✓ Campo 'name' agregado</p>";
                
                // Agregar campo email si no existe
                $pdo->exec("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS email VARCHAR(100) DEFAULT NULL");
                echo "<p class='success'>✓ Campo 'email' agregado</p>";
                
                // Actualizar usuario admin
                $pdo->exec("UPDATE usuarios SET role = 'SuperUser', active = 1, privileges = '{\"all\": true}' WHERE username = 'admin'");
                echo "<p class='success'>✓ Usuario admin actualizado a SuperUser</p>";
                
                break;
                
            case 'create_missing_tables':
                // Crear tabla sessions
                $pdo->exec("CREATE TABLE IF NOT EXISTS sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    session_token VARCHAR(255) UNIQUE NOT NULL,
                    expires_at DATETIME NOT NULL,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_token (session_token),
                    INDEX idx_expires (expires_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
                echo "<p class='success'>✓ Tabla 'sessions' creada</p>";
                
                // Crear tabla relay_control
                $pdo->exec("CREATE TABLE IF NOT EXISTS relay_control (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    device_id VARCHAR(50) NOT NULL,
                    relay_number INT NOT NULL,
                    status ENUM('on', 'off') DEFAULT 'off',
                    last_changed DATETIME,
                    changed_by INT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_device (device_id),
                    INDEX idx_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
                echo "<p class='success'>✓ Tabla 'relay_control' creada</p>";
                
                // Crear tabla system_settings
                $pdo->exec("CREATE TABLE IF NOT EXISTS system_settings (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    setting_key VARCHAR(100) UNIQUE NOT NULL,
                    setting_value TEXT,
                    setting_type VARCHAR(50) DEFAULT 'string',
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_key (setting_key)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
                echo "<p class='success'>✓ Tabla 'system_settings' creada</p>";
                
                // Crear tabla system_logs
                $pdo->exec("CREATE TABLE IF NOT EXISTS system_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    level VARCHAR(20) NOT NULL,
                    message TEXT NOT NULL,
                    context JSON,
                    user_id INT,
                    username VARCHAR(50),
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_level (level),
                    INDEX idx_created (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
                echo "<p class='success'>✓ Tabla 'system_logs' creada</p>";
                
                break;
        }
        
        echo '<p><a href="diagnose.php">🔄 Volver a ejecutar diagnóstico</a></p>';
        
    } catch (PDOException $e) {
        echo "<p class='error'>Error aplicando corrección: " . htmlspecialchars($e->getMessage()) . "</p>";
    }
    
    echo '</div>';
}

?>

<div class="section">
    <h2>Enlaces Útiles</h2>
    <ul>
        <li><a href="/test_connection.php">Test de Conexión Original</a></li>
        <li><a href="/test_login_minimal.php">Test Login Mínimo</a></li>
        <li><a href="/login/index_login.html">Página de Login</a></li>
        <li><a href="/phpinfo.php">PHP Info</a> (si existe)</li>
    </ul>
</div>

<script>
// Auto-scroll para ver errores
if (document.querySelector('.error')) {
    document.querySelector('.error').scrollIntoView();
}
</script>

</body>
</html>
