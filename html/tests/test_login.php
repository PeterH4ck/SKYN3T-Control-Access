<?php
/**
 * Script de prueba de login
 * Ubicación: /var/www/html/test_login.php
 * Uso: php test_login.php [usuario] [contraseña]
 */

// Colores para CLI
$GREEN = "\033[0;32m";
$RED = "\033[0;31m";
$YELLOW = "\033[1;33m";
$BLUE = "\033[0;34m";
$NC = "\033[0m"; // No Color

// Configuración
$db_host = 'localhost';
$db_user = 'admin';
$db_pass = 'root123';
$db_name = 'relay_control';

echo "${BLUE}=== Test de Sistema de Login ===${NC}\n\n";

// 1. Verificar conexión a base de datos
echo "${YELLOW}1. Probando conexión a MySQL...${NC}\n";
try {
    $conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
    if ($conn->connect_error) {
        throw new Exception("Connection failed: " . $conn->connect_error);
    }
    echo "${GREEN}✓ Conexión exitosa${NC}\n";
    $conn->set_charset("utf8mb4");
} catch (Exception $e) {
    echo "${RED}✗ Error de conexión: " . $e->getMessage() . "${NC}\n";
    exit(1);
}

// 2. Verificar tabla usuarios
echo "\n${YELLOW}2. Verificando tabla usuarios...${NC}\n";
$result = $conn->query("SHOW TABLES LIKE 'usuarios'");
if ($result->num_rows > 0) {
    echo "${GREEN}✓ Tabla 'usuarios' existe${NC}\n";
    
    // Mostrar estructura
    echo "${BLUE}  Estructura:${NC}\n";
    $result = $conn->query("DESCRIBE usuarios");
    while ($row = $result->fetch_assoc()) {
        echo "  - {$row['Field']} ({$row['Type']})\n";
    }
} else {
    echo "${RED}✗ Tabla 'usuarios' no existe${NC}\n";
    exit(1);
}

// 3. Listar usuarios existentes
echo "\n${YELLOW}3. Usuarios en la base de datos:${NC}\n";
$result = $conn->query("SELECT id, username, is_active, 
    CASE 
        WHEN LENGTH(password) = 64 AND password REGEXP '^[a-fA-F0-9]+$' THEN 'SHA256'
        WHEN password LIKE '$2y$%' THEN 'bcrypt'
        WHEN password LIKE '$argon%' THEN 'Argon2'
        ELSE 'Desconocido'
    END as hash_type,
    created_at
    FROM usuarios");

if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $status = $row['is_active'] ? "${GREEN}Activo${NC}" : "${RED}Inactivo${NC}";
        echo "  - ID: {$row['id']}, Usuario: {$row['username']}, Estado: $status, Hash: {$row['hash_type']}\n";
    }
} else {
    echo "${RED}  No hay usuarios en la base de datos${NC}\n";
}

// 4. Probar login
echo "\n${YELLOW}4. Prueba de autenticación:${NC}\n";

// Obtener credenciales
if ($argc >= 3) {
    $test_user = $argv[1];
    $test_pass = $argv[2];
} else {
    // Usar credenciales por defecto
    $test_user = 'admin';
    $test_pass = 'admin123';
    echo "  Usando credenciales por defecto: $test_user / $test_pass\n";
}

// Buscar usuario
$stmt = $conn->prepare("SELECT id, password, is_active FROM usuarios WHERE username = ?");
$stmt->bind_param('s', $test_user);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

if (!$user) {
    echo "${RED}✗ Usuario '$test_user' no encontrado${NC}\n";
} else {
    echo "${GREEN}✓ Usuario encontrado${NC}\n";
    
    // Verificar si está activo
    if ($user['is_active'] != 1) {
        echo "${RED}✗ Usuario inactivo${NC}\n";
    } else {
        echo "${GREEN}✓ Usuario activo${NC}\n";
        
        // Verificar contraseña
        $stored_hash = $user['password'];
        $is_valid = false;
        $hash_type = '';
        
        // Detectar tipo de hash y verificar
        if (strlen($stored_hash) === 64 && ctype_xdigit($stored_hash)) {
            // SHA256 legacy
            $hash_type = 'SHA256';
            $test_hash = hash('sha256', $test_pass);
            $is_valid = ($stored_hash === $test_hash);
            echo "  Tipo de hash: SHA256 (legacy)\n";
        } else {
            // Hash moderno (bcrypt/Argon2)
            $hash_type = 'bcrypt/Argon2';
            $is_valid = password_verify($test_pass, $stored_hash);
            echo "  Tipo de hash: Moderno (bcrypt/Argon2)\n";
        }
        
        if ($is_valid) {
            echo "${GREEN}✓ ¡Contraseña correcta! Login exitoso${NC}\n";
        } else {
            echo "${RED}✗ Contraseña incorrecta${NC}\n";
            
            // Ofrecer actualizar hash si estamos en CLI
            if (php_sapi_name() === 'cli' && $user['id']) {
                echo "\n${YELLOW}¿Desea resetear la contraseña? (s/n): ${NC}";
                $handle = fopen("php://stdin", "r");
                $line = fgets($handle);
                if (trim($line) == 's') {
                    // Generar nuevo hash
                    $new_hash = password_hash($test_pass, PASSWORD_BCRYPT);
                    $update_stmt = $conn->prepare("UPDATE usuarios SET password = ? WHERE id = ?");
                    $update_stmt->bind_param('si', $new_hash, $user['id']);
                    if ($update_stmt->execute()) {
                        echo "${GREEN}✓ Contraseña actualizada exitosamente${NC}\n";
                    }
                }
                fclose($handle);
            }
        }
    }
}

// 5. Verificar archivos del sistema de login
echo "\n${YELLOW}5. Verificando archivos del sistema:${NC}\n";
$files_to_check = [
    '/var/www/html/login/login.php' => 'Script de login',
    '/var/www/html/login/index.html' => 'Página de login',
    '/var/www/html/includes/database.php' => 'Clase Database',
    '/var/www/html/includes/auth.php' => 'Funciones de autenticación'
];

foreach ($files_to_check as $file => $desc) {
    if (file_exists($file)) {
        echo "${GREEN}✓ $desc existe${NC}\n";
    } else {
        echo "${RED}✗ $desc no encontrado${NC} ($file)\n";
    }
}

// 6. Probar login via HTTP (si estamos en CLI)
if (php_sapi_name() === 'cli') {
    echo "\n${YELLOW}6. Probando login via HTTP...${NC}\n";
    
    $login_url = 'http://localhost/login/login.php';
    $post_data = http_build_query([
        'username' => $test_user,
        'password' => $test_pass
    ]);
    
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
            'content' => $post_data
        ]
    ]);
    
    $response = @file_get_contents($login_url, false, $context);
    
    if ($response !== false) {
        $json = json_decode($response, true);
        if ($json && isset($json['success'])) {
            if ($json['success']) {
                echo "${GREEN}✓ Login HTTP exitoso${NC}\n";
                echo "  Respuesta: " . json_encode($json, JSON_PRETTY_PRINT) . "\n";
            } else {
                echo "${RED}✗ Login HTTP falló: {$json['message']}${NC}\n";
            }
        } else {
            echo "${YELLOW}⚠ Respuesta inesperada del servidor${NC}\n";
        }
    } else {
        echo "${RED}✗ No se pudo conectar al servidor HTTP${NC}\n";
    }
}

// Cerrar conexión
$conn->close();

echo "\n${BLUE}=== Test completado ===${NC}\n";
?>