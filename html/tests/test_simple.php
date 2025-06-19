<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h1>Test Simple SKYN3T</h1>";
echo "<p>Si ves esto, PHP funciona correctamente.</p>";

// Test de conexión directa
try {
    $pdo = new PDO("mysql:host=localhost;dbname=skyn3t_db", "admin", "admin");
    echo "<p style='color:green'>✓ Conexión a base de datos: OK</p>";
    
    // Verificar usuario admin
    $stmt = $pdo->query("SELECT username, role FROM usuarios WHERE username = 'admin'");
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    echo "<p>Usuario admin: " . $user['username'] . " - Rol: " . $user['role'] . "</p>";
    
} catch (Exception $e) {
    echo "<p style='color:red'>✗ Error de conexión: " . $e->getMessage() . "</p>";
}

// Verificar archivos
$files = [
    '/var/www/html/includes/config.php',
    '/var/www/html/includes/database.php',
    '/var/www/html/includes/functions.php',
    '/var/www/html/includes/auth.php',
    '/var/www/html/includes/init.php'
];

echo "<h2>Verificación de archivos:</h2>";
foreach ($files as $file) {
    if (file_exists($file)) {
        echo "<p style='color:green'>✓ " . basename($file) . " existe</p>";
    } else {
        echo "<p style='color:red'>✗ " . basename($file) . " NO existe</p>";
    }
}

echo "<p><a href='/login/index_login.html'>Ir al Login</a></p>";
?>
