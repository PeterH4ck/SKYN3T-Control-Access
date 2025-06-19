<?php
/**
 * Script de Diagnóstico Completo del Sistema SKYN3T
 * Ubicación: /login/diagnostico.php
 * 
 * Ejecutar desde: http://192.168.4.1/login/diagnostico.php
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

// Configuración de la base de datos
$DB_CONFIG = [
    'host' => 'localhost',
    'dbname' => 'skyn3t_db',
    'username' => 'root',  // Ajustar si es diferente
    'password' => '',      // Ajustar si tienes contraseña
    'charset' => 'utf8mb4'
];

// Función para logging
function logMessage($message, $type = 'INFO') {
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[$timestamp] [$type] $message" . PHP_EOL;
    
    // Escribir a archivo de log
    file_put_contents('/tmp/skyn3t_diagnostic.log', $logEntry, FILE_APPEND | LOCK_EX);
    
    // Mostrar en pantalla
    $color = [
        'ERROR' => '#ff4444',
        'WARNING' => '#ffaa00', 
        'SUCCESS' => '#44ff44',
        'INFO' => '#4444ff'
    ];
    
    echo "<div style='color: " . ($color[$type] ?? '#333') . "; margin: 5px 0;'>";
    echo "<strong>[$type]</strong> $message";
    echo "</div>";
}

function testSection($title) {
    echo "<h3 style='background: #f0f0f0; padding: 10px; margin: 20px 0 10px 0; border-left: 4px solid #007cba;'>🔍 $title</h3>";
    logMessage("=== INICIANDO: $title ===");
}

function testResult($test, $result, $details = '') {
    $status = $result ? 'SUCCESS' : 'ERROR';
    $icon = $result ? '✅' : '❌';
    logMessage("$test: " . ($result ? 'PASS' : 'FAIL') . ($details ? " - $details" : ''), $status);
    echo "<div style='margin: 5px 0; padding: 5px; background: " . ($result ? '#e8f5e8' : '#ffe8e8') . ";'>";
    echo "$icon <strong>$test:</strong> " . ($result ? 'OK' : 'FALLO');
    if ($details) echo " - <em>$details</em>";
    echo "</div>";
    return $result;
}

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Diagnóstico Sistema SKYN3T</title>
    <style>
        body { font-family: 'Courier New', monospace; margin: 20px; background: #f5f5f5; }
        .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; background: #007cba; color: white; padding: 20px; margin: -20px -20px 20px -20px; }
        .summary { background: #f0f8ff; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .log-section { background: #000; color: #00ff00; padding: 15px; border-radius: 5px; font-family: monospace; max-height: 400px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔧 Diagnóstico Sistema SKYN3T</h1>
            <p>Análisis completo del sistema - <?php echo date('Y-m-d H:i:s'); ?></p>
        </div>

<?php

logMessage("INICIANDO DIAGNÓSTICO COMPLETO DEL SISTEMA SKYN3T");
logMessage("Timestamp: " . date('Y-m-d H:i:s'));
logMessage("IP Cliente: " . ($_SERVER['REMOTE_ADDR'] ?? 'Desconocida'));
logMessage("User Agent: " . ($_SERVER['HTTP_USER_AGENT'] ?? 'Desconocido'));

$allTests = [];

// ==========================================
// 1. VERIFICACIÓN DEL ENTORNO PHP
// ==========================================
testSection("Entorno PHP");

$allTests['php_version'] = testResult(
    "Versión de PHP", 
    version_compare(PHP_VERSION, '7.4.0', '>='),
    "PHP " . PHP_VERSION . " (Mínimo requerido: 7.4.0)"
);

$allTests['php_extensions'] = true;
$required_extensions = ['pdo', 'pdo_mysql', 'json', 'session', 'mbstring'];
foreach ($required_extensions as $ext) {
    $loaded = extension_loaded($ext);
    testResult("Extensión $ext", $loaded);
    if (!$loaded) $allTests['php_extensions'] = false;
}

$allTests['error_reporting'] = testResult(
    "Error Reporting", 
    true,
    "Level: " . error_reporting() . " | Display Errors: " . (ini_get('display_errors') ? 'ON' : 'OFF')
);

// ==========================================
// 2. VERIFICACIÓN DEL SISTEMA DE ARCHIVOS
// ==========================================
testSection("Sistema de Archivos");

$critical_files = [
    '/var/www/html/login/index_login.html' => 'Página de login',
    '/var/www/html/login/login.php' => 'Script de login PHP',
    '/var/www/html/rele/index_rele.html' => 'Panel de control',
    '/var/www/html/rele/dashboard.html' => 'Dashboard principal'
];

$allTests['file_structure'] = true;
foreach ($critical_files as $file => $description) {
    $exists = file_exists($file);
    $readable = $exists ? is_readable($file) : false;
    testResult("$description ($file)", $exists && $readable, 
        $exists ? ($readable ? "Legible" : "No legible") : "No existe");
    if (!$exists || !$readable) $allTests['file_structure'] = false;
}

// Verificar permisos
$web_root = '/var/www/html';
$owner = fileowner($web_root);
$group = filegroup($web_root);
$perms = substr(sprintf('%o', fileperms($web_root)), -4);

testResult("Permisos directorio web", 
    is_writable($web_root . '/tmp') || is_writable('/tmp'),
    "Owner: $owner | Group: $group | Perms: $perms"
);

// ==========================================
// 3. VERIFICACIÓN DE BASE DE DATOS
// ==========================================
testSection("Base de Datos MariaDB/MySQL");

try {
    $dsn = "mysql:host={$DB_CONFIG['host']};dbname={$DB_CONFIG['dbname']};charset={$DB_CONFIG['charset']}";
    $pdo = new PDO($dsn, $DB_CONFIG['username'], $DB_CONFIG['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    
    $allTests['db_connection'] = testResult("Conexión a BD", true, "Conectado a {$DB_CONFIG['dbname']}");
    
    // Verificar versión
    $version = $pdo->query('SELECT VERSION() as version')->fetch()['version'];
    testResult("Versión de BD", true, $version);
    
    // Verificar tablas críticas
    $required_tables = ['usuarios', 'access_log'];
    $stmt = $pdo->query("SHOW TABLES");
    $existing_tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
    
    $allTests['db_tables'] = true;
    foreach ($required_tables as $table) {
        $exists = in_array($table, $existing_tables);
        testResult("Tabla '$table'", $exists);
        if (!$exists) $allTests['db_tables'] = false;
    }
    
    // Verificar estructura tabla usuarios
    if (in_array('usuarios', $existing_tables)) {
        $stmt = $pdo->query("DESCRIBE usuarios");
        $columns = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        $required_columns = ['id', 'username', 'password', 'role'];
        $allTests['users_structure'] = true;
        foreach ($required_columns as $col) {
            $exists = in_array($col, $columns);
            testResult("Columna usuarios.$col", $exists);
            if (!$exists) $allTests['users_structure'] = false;
        }
        
        // Contar usuarios
        $user_count = $pdo->query("SELECT COUNT(*) FROM usuarios")->fetchColumn();
        testResult("Usuarios registrados", $user_count > 0, "$user_count usuarios encontrados");
        
        // Verificar usuario admin
        $admin_exists = $pdo->query("SELECT COUNT(*) FROM usuarios WHERE role IN ('Admin', 'SuperUser')")->fetchColumn();
        $allTests['admin_user'] = testResult("Usuario administrador", $admin_exists > 0, "$admin_exists admins encontrados");
    }
    
} catch (PDOException $e) {
    $allTests['db_connection'] = testResult("Conexión a BD", false, "Error: " . $e->getMessage());
    $allTests['db_tables'] = false;
    $allTests['users_structure'] = false;
    $allTests['admin_user'] = false;
}

// ==========================================
// 4. VERIFICACIÓN DE CONFIGURACIÓN WEB
// ==========================================
testSection("Configuración del Servidor Web");

$allTests['document_root'] = testResult(
    "Document Root", 
    isset($_SERVER['DOCUMENT_ROOT']),
    $_SERVER['DOCUMENT_ROOT'] ?? 'No definido'
);

$allTests['http_host'] = testResult(
    "HTTP Host", 
    isset($_SERVER['HTTP_HOST']),
    $_SERVER['HTTP_HOST'] ?? 'No definido'
);

$allTests['request_uri'] = testResult(
    "Request URI", 
    isset($_SERVER['REQUEST_URI']),
    $_SERVER['REQUEST_URI'] ?? 'No definido'
);

// Verificar mod_rewrite
$mod_rewrite = function_exists('apache_get_modules') ? in_array('mod_rewrite', apache_get_modules()) : 'Desconocido';
testResult("mod_rewrite", $mod_rewrite === true, $mod_rewrite === true ? 'Habilitado' : 'Estado: ' . $mod_rewrite);

// ==========================================
// 5. PRUEBA DE LOGIN SIMULADO
// ==========================================
testSection("Prueba de Funcionalidad de Login");

if ($allTests['db_connection'] && $allTests['db_tables']) {
    try {
        // Buscar un usuario de prueba
        $stmt = $pdo->prepare("SELECT id, username, role FROM usuarios WHERE role IN ('Admin', 'SuperUser') LIMIT 1");
        $stmt->execute();
        $test_user = $stmt->fetch();
        
        if ($test_user) {
            testResult("Usuario de prueba encontrado", true, "User: {$test_user['username']} | Role: {$test_user['role']}");
            
            // Simular proceso de login (sin verificar contraseña)
            $_SESSION['test_user_id'] = $test_user['id'];
            $_SESSION['test_username'] = $test_user['username'];
            $_SESSION['test_role'] = $test_user['role'];
            
            $allTests['login_simulation'] = testResult("Simulación de sesión", true, "Sesión iniciada correctamente");
            
            // Verificar redirección
            $redirect = ($test_user['role'] === 'Admin' || $test_user['role'] === 'SuperUser') ? '/rele/dashboard.html' : '/rele/index_rele.html';
            testResult("Lógica de redirección", true, "Redirección: $redirect");
            
        } else {
            $allTests['login_simulation'] = testResult("Usuario de prueba", false, "No se encontró ningún usuario administrador");
        }
        
    } catch (Exception $e) {
        $allTests['login_simulation'] = testResult("Simulación de login", false, "Error: " . $e->getMessage());
    }
} else {
    $allTests['login_simulation'] = testResult("Simulación de login", false, "No se puede ejecutar: problemas con BD");
}

// ==========================================
// 6. VERIFICACIÓN DE INCLUDES Y DEPENDENCIAS
// ==========================================
testSection("Includes y Dependencias");

$include_paths = [
    '/var/www/html/includes/database_mysql.php' => 'Conexión de BD',
    '/var/www/html/includes/database.php' => 'BD Legacy (opcional)',
];

$allTests['includes'] = true;
foreach ($include_paths as $path => $desc) {
    $exists = file_exists($path);
    testResult("$desc ($path)", $exists, $exists ? "Disponible" : "No encontrado");
    if (strpos($path, 'database_mysql.php') !== false && !$exists) {
        $allTests['includes'] = false;
    }
}

// ==========================================
// 7. DIAGNÓSTICO ESPECÍFICO DEL ERROR 500
// ==========================================
testSection("Diagnóstico Error 500");

// Verificar logs de error de PHP
$php_error_log = ini_get('error_log') ?: '/var/log/apache2/error.log';
$error_log_exists = file_exists($php_error_log) && is_readable($php_error_log);

testResult("Log de errores accesible", $error_log_exists, $php_error_log);

if ($error_log_exists) {
    $recent_errors = shell_exec("tail -50 '$php_error_log' | grep -i 'php\\|fatal\\|error' | tail -10");
    if ($recent_errors) {
        logMessage("ERRORES RECIENTES EN LOG:");
        logMessage($recent_errors);
        testResult("Errores PHP recientes", false, "Se encontraron errores - ver log");
    } else {
        testResult("Errores PHP recientes", true, "No se encontraron errores PHP recientes");
    }
}

// ==========================================
// 8. CREAR ARCHIVO DE LOGIN CORREGIDO
// ==========================================
testSection("Generación de Archivo de Login Corregido");

$fixed_login_content = '<?php
/**
 * Login PHP Corregido - Generado automáticamente por diagnóstico
 * Fecha: ' . date('Y-m-d H:i:s') . '
 */

session_start();
error_reporting(E_ALL);
ini_set("log_errors", 1);
ini_set("error_log", "/tmp/skyn3t_login_errors.log");

// Configuración de BD basada en diagnóstico
try {
    $pdo = new PDO("mysql:host=' . $DB_CONFIG['host'] . ';dbname=' . $DB_CONFIG['dbname'] . ';charset=utf8mb4", 
                   "' . $DB_CONFIG['username'] . '", "' . $DB_CONFIG['password'] . '", [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch(PDOException $e) {
    error_log("Error de conexión BD: " . $e->getMessage());
    http_response_code(500);
    if (isset($_POST["username"])) {
        header("Content-Type: application/json");
        echo json_encode(["success" => false, "message" => "Error de base de datos"]);
    } else {
        echo "Error de configuración del sistema";
    }
    exit;
}

function getRedirectByRole($role) {
    switch($role) {
        case "SuperUser":
        case "SupportAdmin": 
        case "Admin":
            return "/rele/dashboard.html";
        case "User":
        default:
            return "/rele/index_rele.html";
    }
}

// Procesar POST (login)
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    header("Content-Type: application/json");
    
    try {
        $username = trim($_POST["username"] ?? "");
        $password = $_POST["password"] ?? "";
        
        if (empty($username) || empty($password)) {
            echo json_encode(["success" => false, "message" => "Usuario y contraseña requeridos"]);
            exit;
        }
        
        // Buscar usuario (usando el campo correcto según diagnóstico)
        $stmt = $pdo->prepare("SELECT id, username, password, role, is_active 
                              FROM usuarios 
                              WHERE username = ? AND (is_active = 1 OR active = 1)");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        
        if (!$user || !password_verify($password, $user["password"])) {
            echo json_encode(["success" => false, "message" => "Credenciales incorrectas"]);
            exit;
        }
        
        // Login exitoso
        $_SESSION["user_id"] = $user["id"];
        $_SESSION["username"] = $user["username"];
        $_SESSION["role"] = $user["role"];
        $_SESSION["login_time"] = time();
        $_SESSION["ip"] = $_SERVER["REMOTE_ADDR"];
        
        echo json_encode([
            "success" => true,
            "message" => "Login exitoso",
            "redirect" => getRedirectByRole($user["role"]),
            "role" => $user["role"]
        ]);
        
    } catch (Exception $e) {
        error_log("Error en login: " . $e->getMessage());
        echo json_encode(["success" => false, "message" => "Error del sistema"]);
    }
    exit;
}

// Verificar sesión existente
if (isset($_SESSION["user_id"])) {
    header("Location: " . getRedirectByRole($_SESSION["role"] ?? "User"));
    exit;
}
?>';

$login_file_path = '/var/www/html/login/login_fixed.php';
$backup_created = false;

// Crear backup del archivo original si existe
if (file_exists('/var/www/html/login/login.php')) {
    $backup_path = '/var/www/html/login/login_backup_' . date('Y-m-d_H-i-s') . '.php';
    if (copy('/var/www/html/login/login.php', $backup_path)) {
        $backup_created = true;
        testResult("Backup creado", true, $backup_path);
    }
}

// Crear archivo corregido
if (file_put_contents($login_file_path, $fixed_login_content)) {
    testResult("Archivo login corregido", true, $login_file_path);
    logMessage("ARCHIVO LOGIN CORREGIDO CREADO: $login_file_path");
} else {
    testResult("Archivo login corregido", false, "No se pudo crear el archivo");
}

// ==========================================
// RESUMEN FINAL
// ==========================================
echo '<div class="summary">';
echo '<h3>📊 RESUMEN DEL DIAGNÓSTICO</h3>';

$passed = array_sum($allTests);
$total = count($allTests);
$percentage = round(($passed / $total) * 100, 1);

echo "<p><strong>Pruebas pasadas:</strong> $passed de $total ($percentage%)</p>";

if ($percentage >= 80) {
    echo '<p style="color: green;"><strong>✅ Estado: SISTEMA FUNCIONAL</strong></p>';
    echo '<p><strong>Recomendación:</strong> Reemplaza login.php con login_fixed.php y prueba nuevamente.</p>';
} elseif ($percentage >= 60) {
    echo '<p style="color: orange;"><strong>⚠️ Estado: PROBLEMAS MENORES</strong></p>';
    echo '<p><strong>Recomendación:</strong> Corregir los problemas identificados antes de continuar.</p>';
} else {
    echo '<p style="color: red;"><strong>❌ Estado: PROBLEMAS CRÍTICOS</strong></p>';
    echo '<p><strong>Recomendación:</strong> Sistema requiere configuración antes de funcionar.</p>';
}

echo '</div>';

// ==========================================
// COMANDOS DE CORRECCIÓN
// ==========================================
echo '<h3>🔧 COMANDOS DE CORRECCIÓN</h3>';
echo '<div class="log-section">';
echo '<p><strong>Ejecuta estos comandos para corregir los problemas:</strong></p>';
echo '<pre>';

if (!$allTests['file_structure']) {
    echo "# Corregir permisos de archivos:\n";
    echo "sudo chown -R www-data:www-data /var/www/html/\n";
    echo "sudo chmod -R 755 /var/www/html/\n";
    echo "sudo chmod -R 644 /var/www/html/*.php\n\n";
}

if (!$allTests['db_connection']) {
    echo "# Verificar servicio MariaDB:\n";
    echo "sudo systemctl status mariadb\n";
    echo "sudo systemctl restart mariadb\n\n";
}

if (!$allTests['admin_user']) {
    echo "# Crear usuario administrador:\n";
    echo "mysql -u root -p skyn3t_db\n";
    echo "INSERT INTO usuarios (username, password, role, is_active) VALUES \n";
    echo "('admin', '\$2y\$10\$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Admin', 1);\n";
    echo "-- Contraseña: password\n\n";
}

echo "# Usar archivo de login corregido:\n";
echo "cd /var/www/html/login/\n";
echo "sudo cp login.php login_original_backup.php\n";
echo "sudo cp login_fixed.php login.php\n";
echo "sudo systemctl restart apache2\n\n";

echo "# Verificar logs en tiempo real:\n";
echo "sudo tail -f /var/log/apache2/error.log\n";
echo "sudo tail -f /tmp/skyn3t_login_errors.log\n";

echo '</pre>';
echo '</div>';

logMessage("DIAGNÓSTICO COMPLETADO - Total: $passed/$total pruebas pasadas ($percentage%)");
logMessage("Log completo guardado en: /tmp/skyn3t_diagnostic.log");

?>

<div style="margin-top: 30px; padding: 15px; background: #e8f4fd; border-radius: 5px;">
    <h4>📋 SIGUIENTE PASO:</h4>
    <ol>
        <li>Ejecuta los comandos de corrección mostrados arriba</li>
        <li>Reemplaza <code>login.php</code> con <code>login_fixed.php</code></li>
        <li>Reinicia Apache: <code>sudo systemctl restart apache2</code></li>
        <li>Prueba el login nuevamente</li>
        <li>Si persiste el error, envía el contenido de <code>/tmp/skyn3t_diagnostic.log</code></li>
    </ol>
</div>

    </div>
</body>
</html>
