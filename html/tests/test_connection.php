<?php
// Test de conexión SKYN3T
echo "<h1>Test de Conexión SKYN3T</h1><pre>";

// Test 1: Conexión directa
echo "1. Probando conexión directa a MySQL...\n";
try {
    $pdo = new PDO(
        "mysql:host=localhost;dbname=skyn3t_db;charset=utf8mb4",
        "admin",
        "admin"
    );
    echo "   ✅ Conexión exitosa!\n";
} catch (PDOException $e) {
    echo "   ❌ Error: " . $e->getMessage() . "\n";
}

// Test 2: Sistema SKYN3T
echo "\n2. Probando sistema SKYN3T...\n";
if (file_exists('/var/www/html/includes/init.php')) {
    require_once '/var/www/html/includes/init.php';
    if (defined('SKYN3T_INITIALIZED')) {
        echo "   ✅ Sistema inicializado correctamente\n";
    } else {
        echo "   ❌ Error al inicializar sistema\n";
    }
} else {
    echo "   ❌ Archivo init.php no encontrado\n";
}

echo "</pre>";
?>
