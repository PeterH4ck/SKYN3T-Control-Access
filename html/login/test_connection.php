<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

try {
    $pdo = new PDO("mysql:host=localhost;dbname=skyn3t_db;charset=utf8", "root", "");
    echo "✅ Conexión exitosa a skyn3t_db<br>";
    
    $stmt = $pdo->query("SELECT COUNT(*) as total FROM usuarios");
    $result = $stmt->fetch();
    echo "👥 Total usuarios: " . $result['total'] . "<br>";
    
    $stmt = $pdo->query("SELECT username, role FROM usuarios LIMIT 5");
    echo "<br>📋 Usuarios encontrados:<br>";
    while ($row = $stmt->fetch()) {
        echo "- " . $row['username'] . " (" . $row['role'] . ")<br>";
    }
    
} catch(PDOException $e) {
    echo "❌ Error: " . $e->getMessage();
}
?>
