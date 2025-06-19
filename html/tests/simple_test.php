<?php
echo "<h1>Diagnóstico Simple SKYN3T</h1>";

// Test 1: Conexión BD
try {
    $pdo = new PDO("mysql:host=localhost;dbname=skyn3t_db;charset=utf8mb4", "root", "");
    echo "<p>✅ Conexión BD: OK</p>";
    
    // Test tablas
    $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
    echo "<p>📋 Tablas encontradas: " . implode(", ", $tables) . "</p>";
    
    if (in_array('usuarios', $tables)) {
        $count = $pdo->query("SELECT COUNT(*) FROM usuarios")->fetchColumn();
        echo "<p>👥 Usuarios en BD: $count</p>";
    }
    
} catch (Exception $e) {
    echo "<p>❌ Error BD: " . $e->getMessage() . "</p>";
}

// Test 2: Archivos críticos
$files = [
    '/var/www/html/login/index_login.html',
    '/var/www/html/login/login.php',
    '/var/www/html/rele/index_rele.html'
];

echo "<h3>Archivos críticos:</h3>";
foreach ($files as $file) {
    $status = file_exists($file) ? "✅ Existe" : "❌ No existe";
    echo "<p>$file: $status</p>";
}

// Test 3: Logs recientes
echo "<h3>Información del sistema:</h3>";
echo "<p>Document Root: " . $_SERVER['DOCUMENT_ROOT'] . "</p>";
echo "<p>Script: " . $_SERVER['SCRIPT_NAME'] . "</p>";
?>
