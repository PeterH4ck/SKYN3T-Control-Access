<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "PHP funciona correctamente<br>";
echo "Versión PHP: " . phpversion() . "<br>";

// Probar conexión a BD
try {
    $pdo = new PDO("mysql:host=localhost;dbname=TU_BD", "TU_USUARIO", "TU_CONTRASEÑA");
    echo "Conexión a BD: ✅ OK<br>";
    
    $stmt = $pdo->query("SHOW TABLES");
    echo "Tablas en la BD:<br>";
    while ($row = $stmt->fetch()) {
        echo "- " . $row[0] . "<br>";
    }
} catch(PDOException $e) {
    echo "Error de BD: " . $e->getMessage() . "<br>";
}
?>
