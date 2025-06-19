<?php
/**
 * SKYN3T - Herramienta de Diagnóstico Completa
 * Versión: 3.0.0
 * Descripción: Análisis completo del sistema, base de datos y archivos
 */

// Configuración inicial
error_reporting(E_ALL);
ini_set('display_errors', 1);
date_default_timezone_set('America/Santiago');

// Configuración de base de datos
define('DB_HOST', 'localhost');
define('DB_NAME', 'skyn3t_db');
define('DB_USER', 'skyn3t_app');
define('DB_PASS', 'Skyn3t2025!');

// Iniciar sesión para tests
session_start();

// Clase principal de diagnóstico
class SKYN3TDiagnostics {
    private $db;
    private $results = [];
    private $errors = [];
    private $warnings = [];
    private $basePath = '/var/www/html';
    
    public function __construct() {
        try {
            $this->db = new PDO(
                "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
                DB_USER,
                DB_PASS,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
                ]
            );
            $this->results['database']['connection'] = '✅ Conectado exitosamente';
        } catch (PDOException $e) {
            $this->errors[] = "❌ Error de conexión a DB: " . $e->getMessage();
            $this->db = null;
        }
    }
    
    /**
     * Ejecutar diagnóstico completo
     */
    public function runFullDiagnostics() {
        $this->checkDatabaseStructure();
        $this->checkUsers();
        $this->checkPermissions();
        $this->checkFiles();
        $this->checkPHPSyntax();
        $this->checkRedirections();
        $this->checkMissingImplementations();
        $this->checkSessions();
        $this->checkSecurity();
        $this->performFunctionalTests();
        
        return $this->generateReport();
    }
    
    /**
     * 1. Verificar estructura de base de datos
     */
    private function checkDatabaseStructure() {
        if (!$this->db) return;
        
        $this->results['database']['structure'] = [];
        
        // Tablas esperadas
        $expectedTables = [
            'users' => ['id', 'username', 'password', 'role', 'active', 'created_at', 'last_login'],
            'sessions' => ['session_id', 'user_id', 'created_at', 'last_activity'],
            'access_log' => ['id', 'username', 'action', 'timestamp', 'ip_address'],
            'devices' => ['id', 'name', 'type', 'status', 'location'],
            'relay_status' => ['id', 'relay_state', 'led_state', 'changed_by', 'timestamp']
        ];
        
        // Obtener todas las tablas
        $stmt = $this->db->query("SHOW TABLES");
        $existingTables = $stmt->fetchAll(PDO::FETCH_COLUMN);
        $this->results['database']['total_tables'] = count($existingTables);
        
        foreach ($expectedTables as $table => $expectedColumns) {
            if (in_array($table, $existingTables)) {
                // Verificar columnas
                $stmt = $this->db->query("DESCRIBE $table");
                $columns = $stmt->fetchAll(PDO::FETCH_COLUMN);
                
                $missingColumns = array_diff($expectedColumns, $columns);
                
                if (empty($missingColumns)) {
                    $this->results['database']['structure'][$table] = '✅ OK';
                } else {
                    $this->warnings[] = "⚠️ Tabla '$table' falta columnas: " . implode(', ', $missingColumns);
                    $this->results['database']['structure'][$table] = '⚠️ Columnas faltantes';
                }
            } else {
                $this->errors[] = "❌ Tabla '$table' no existe";
                $this->results['database']['structure'][$table] = '❌ No existe';
            }
        }
        
        // Verificar tablas extras
        $extraTables = array_diff($existingTables, array_keys($expectedTables));
        if (!empty($extraTables)) {
            $this->results['database']['extra_tables'] = $extraTables;
        }
    }
    
    /**
     * 2. Verificar usuarios
     */
    private function checkUsers() {
        if (!$this->db) return;
        
        try {
            $stmt = $this->db->query("SELECT username, role, active, last_login FROM users ORDER BY id");
            $users = $stmt->fetchAll();
            
            $this->results['users']['total'] = count($users);
            $this->results['users']['list'] = [];
            
            $roleCount = [];
            $activeCount = 0;
            
            foreach ($users as $user) {
                $status = $user['active'] ? '✅ Activo' : '❌ Inactivo';
                $lastLogin = $user['last_login'] ?? 'Nunca';
                
                $this->results['users']['list'][] = [
                    'username' => $user['username'],
                    'role' => $user['role'],
                    'status' => $status,
                    'last_login' => $lastLogin
                ];
                
                // Contar por rol
                $roleCount[$user['role']] = ($roleCount[$user['role']] ?? 0) + 1;
                if ($user['active']) $activeCount++;
            }
            
            $this->results['users']['by_role'] = $roleCount;
            $this->results['users']['active_count'] = $activeCount;
            
            // Verificar usuarios críticos
            $criticalUsers = ['admin', 'peterh4ck'];
            foreach ($criticalUsers as $criticalUser) {
                $found = false;
                foreach ($users as $user) {
                    if ($user['username'] === $criticalUser && $user['active']) {
                        $found = true;
                        break;
                    }
                }
                if (!$found) {
                    $this->warnings[] = "⚠️ Usuario crítico '$criticalUser' no encontrado o inactivo";
                }
            }
            
        } catch (PDOException $e) {
            $this->errors[] = "❌ Error verificando usuarios: " . $e->getMessage();
        }
    }
    
    /**
     * 3. Verificar permisos y roles
     */
    private function checkPermissions() {
        $this->results['permissions'] = [];
        
        $definedRoles = ['SuperUser', 'Admin', 'SupportAdmin', 'User'];
        $roleHierarchy = [
            'SuperUser' => 4,
            'Admin' => 3,
            'SupportAdmin' => 2,
            'User' => 1
        ];
        
        // Verificar roles en base de datos
        if ($this->db) {
            try {
                $stmt = $this->db->query("SELECT DISTINCT role FROM users");
                $dbRoles = $stmt->fetchAll(PDO::FETCH_COLUMN);
                
                $undefinedRoles = array_diff($dbRoles, $definedRoles);
                if (!empty($undefinedRoles)) {
                    $this->warnings[] = "⚠️ Roles no definidos en sistema: " . implode(', ', $undefinedRoles);
                }
                
                $this->results['permissions']['defined_roles'] = $definedRoles;
                $this->results['permissions']['db_roles'] = $dbRoles;
                $this->results['permissions']['hierarchy'] = $roleHierarchy;
                
            } catch (PDOException $e) {
                $this->errors[] = "❌ Error verificando roles: " . $e->getMessage();
            }
        }
    }
    
    /**
     * 4. Verificar archivos del sistema
     */
    private function checkFiles() {
        $this->results['files'] = [];
        
        $criticalPaths = [
            '/login/login.php' => 'Sistema de autenticación',
            '/login/index_login.html' => 'Página de login',
            '/dashboard/dashboard.html' => 'Dashboard administrativo',
            '/dashboard/check_dashboard_access.php' => 'Verificación de acceso',
            '/rele/index_rele.html' => 'Panel de control de relé',
            '/includes/config.php' => 'Configuración del sistema',
            '/includes/database.php' => 'Conexión a base de datos',
            '/api/relay/status.php' => 'API estado del relé',
            '/images/logo.png' => 'Logo del sistema',
            '/images/login-background.jpeg' => 'Fondo de login'
        ];
        
        foreach ($criticalPaths as $path => $description) {
            $fullPath = $this->basePath . $path;
            if (file_exists($fullPath)) {
                $this->results['files'][$path] = [
                    'status' => '✅ Existe',
                    'size' => filesize($fullPath),
                    'modified' => date('Y-m-d H:i:s', filemtime($fullPath)),
                    'permissions' => substr(sprintf('%o', fileperms($fullPath)), -4)
                ];
            } else {
                $this->errors[] = "❌ Archivo crítico no encontrado: $path ($description)";
                $this->results['files'][$path] = ['status' => '❌ No existe'];
            }
        }
        
        // Escanear directorios
        $directories = ['/login', '/dashboard', '/rele', '/api', '/includes', '/images'];
        foreach ($directories as $dir) {
            $fullDir = $this->basePath . $dir;
            if (is_dir($fullDir)) {
                $files = scandir($fullDir);
                $fileCount = count($files) - 2; // Excluir . y ..
                $this->results['directories'][$dir] = [
                    'status' => '✅ Existe',
                    'file_count' => $fileCount
                ];
            } else {
                $this->warnings[] = "⚠️ Directorio no encontrado: $dir";
                $this->results['directories'][$dir] = ['status' => '❌ No existe'];
            }
        }
    }
    
    /**
     * 5. Verificar sintaxis PHP
     */
    private function checkPHPSyntax() {
        $this->results['php_syntax'] = [];
        
        $phpFiles = [
            '/login/login.php',
            '/dashboard/check_dashboard_access.php',
            '/dashboard/logout.php',
            '/includes/config.php',
            '/includes/database.php',
            '/api/relay/status.php'
        ];
        
        foreach ($phpFiles as $file) {
            $fullPath = $this->basePath . $file;
            if (file_exists($fullPath)) {
                $output = [];
                $returnCode = 0;
                exec("php -l " . escapeshellarg($fullPath) . " 2>&1", $output, $returnCode);
                
                if ($returnCode === 0) {
                    $this->results['php_syntax'][$file] = '✅ Sintaxis OK';
                } else {
                    $this->errors[] = "❌ Error de sintaxis en $file: " . implode("\n", $output);
                    $this->results['php_syntax'][$file] = '❌ Error de sintaxis';
                }
            }
        }
    }
    
    /**
     * 6. Verificar redirecciones
     */
    private function checkRedirections() {
        $this->results['redirections'] = [];
        
        // Verificar redirecciones en login.php
        $loginFile = $this->basePath . '/login/login.php';
        if (file_exists($loginFile)) {
            $content = file_get_contents($loginFile);
            
            // Buscar patrones de redirección
            if (strpos($content, '/dashboard/dashboard.html') !== false) {
                $this->results['redirections']['admin_redirect'] = '✅ Dashboard admin configurado';
            } else {
                $this->warnings[] = "⚠️ Redirección a dashboard admin no encontrada en login.php";
            }
            
            if (strpos($content, '/input_data/input.html') !== false) {
                $this->results['redirections']['user_redirect'] = '✅ Panel usuario configurado';
            } else {
                $this->warnings[] = "⚠️ Redirección a panel usuario no encontrada en login.php";
            }
        }
        
        // Verificar check_dashboard_access.php
        $checkFile = $this->basePath . '/dashboard/check_dashboard_access.php';
        if (file_exists($checkFile)) {
            $content = file_get_contents($checkFile);
            
            // Verificar roles permitidos
            if (strpos($content, 'SuperUser') !== false && strpos($content, 'Admin') !== false) {
                $this->results['redirections']['role_check'] = '✅ Verificación de roles OK';
            } else {
                $this->errors[] = "❌ Verificación de roles incorrecta en check_dashboard_access.php";
            }
        }
    }
    
    /**
     * 7. Identificar implementaciones faltantes
     */
    private function checkMissingImplementations() {
        $this->results['missing'] = [];
        
        $requiredImplementations = [
            '/api/devices/list.php' => 'API lista de dispositivos',
            '/api/devices/add.php' => 'API agregar dispositivo',
            '/api/users/list.php' => 'API lista de usuarios',
            '/api/system/stats.php' => 'API estadísticas del sistema',
            '/dashboard/statistics.html' => 'Página de estadísticas',
            '/dashboard/settings.html' => 'Página de configuración',
            '/dashboard/users.html' => 'Gestión de usuarios',
            '/devices/index_devices.html' => 'Gestión de dispositivos',
            '/input_data/input.html' => 'Formulario para usuarios básicos'
        ];
        
        foreach ($requiredImplementations as $path => $description) {
            $fullPath = $this->basePath . $path;
            if (!file_exists($fullPath)) {
                $this->results['missing'][] = [
                    'path' => $path,
                    'description' => $description,
                    'priority' => $this->getPriority($path)
                ];
            }
        }
        
        // Ordenar por prioridad
        usort($this->results['missing'], function($a, $b) {
            return $b['priority'] - $a['priority'];
        });
    }
    
    /**
     * 8. Verificar sesiones activas
     */
    private function checkSessions() {
        if (!$this->db) return;
        
        try {
            // Contar sesiones activas
            $stmt = $this->db->query("SELECT COUNT(*) as count FROM sessions WHERE last_activity > DATE_SUB(NOW(), INTERVAL 30 MINUTE)");
            $activeSessions = $stmt->fetch()['count'];
            
            $this->results['sessions']['active'] = $activeSessions;
            
            // Verificar sesiones huérfanas
            $stmt = $this->db->query("
                SELECT COUNT(*) as count 
                FROM sessions s 
                LEFT JOIN users u ON s.user_id = u.id 
                WHERE u.id IS NULL
            ");
            $orphanSessions = $stmt->fetch()['count'];
            
            if ($orphanSessions > 0) {
                $this->warnings[] = "⚠️ Hay $orphanSessions sesiones huérfanas";
            }
            
            $this->results['sessions']['orphan'] = $orphanSessions;
            
        } catch (PDOException $e) {
            $this->errors[] = "❌ Error verificando sesiones: " . $e->getMessage();
        }
    }
    
    /**
     * 9. Verificar seguridad
     */
    private function checkSecurity() {
        $this->results['security'] = [];
        
        // Verificar archivos sensibles
        $sensitiveFiles = [
            '/.env' => 'Variables de entorno',
            '/config.php' => 'Configuración',
            '/.htaccess' => 'Configuración Apache'
        ];
        
        foreach ($sensitiveFiles as $file => $desc) {
            $fullPath = $this->basePath . $file;
            if (file_exists($fullPath)) {
                $perms = fileperms($fullPath);
                $octal = substr(sprintf('%o', $perms), -4);
                
                if ($octal > '0644') {
                    $this->warnings[] = "⚠️ Permisos muy abiertos en $file: $octal";
                }
            }
        }
        
        // Verificar HTTPS
        $this->results['security']['https'] = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 
            '✅ HTTPS activo' : '⚠️ HTTPS no detectado';
        
        // Verificar headers de seguridad
        $headers = headers_list();
        $securityHeaders = [
            'X-Frame-Options' => false,
            'X-Content-Type-Options' => false,
            'X-XSS-Protection' => false
        ];
        
        foreach ($headers as $header) {
            foreach ($securityHeaders as $secHeader => $found) {
                if (stripos($header, $secHeader) !== false) {
                    $securityHeaders[$secHeader] = true;
                }
            }
        }
        
        foreach ($securityHeaders as $header => $found) {
            $this->results['security']['headers'][$header] = $found ? '✅ Presente' : '❌ Faltante';
        }
    }
    
    /**
     * 10. Tests funcionales
     */
    private function performFunctionalTests() {
        $this->results['functional_tests'] = [];
        
        // Test 1: Conexión a base de datos
        $this->results['functional_tests']['database_connection'] = $this->db ? '✅ OK' : '❌ Fallo';
        
        // Test 2: Creación de sesión
        $_SESSION['test'] = 'test_value';
        $this->results['functional_tests']['session_creation'] = 
            isset($_SESSION['test']) ? '✅ OK' : '❌ Fallo';
        unset($_SESSION['test']);
        
        // Test 3: Escritura en logs
        $logDir = $this->basePath . '/logs';
        if (is_dir($logDir) && is_writable($logDir)) {
            $this->results['functional_tests']['log_writable'] = '✅ OK';
        } else {
            $this->results['functional_tests']['log_writable'] = '❌ No escribible';
            $this->warnings[] = "⚠️ Directorio de logs no escribible";
        }
        
        // Test 4: Verificar API endpoints
        $apis = [
            '/api/?json' => 'API principal',
            '/login/check_session.php' => 'Verificación de sesión'
        ];
        
        foreach ($apis as $endpoint => $desc) {
            $fullPath = $this->basePath . $endpoint;
            $file = explode('?', $endpoint)[0];
            
            if (file_exists($this->basePath . $file)) {
                $this->results['functional_tests']['api_' . md5($endpoint)] = '✅ ' . $desc . ' existe';
            } else {
                $this->results['functional_tests']['api_' . md5($endpoint)] = '❌ ' . $desc . ' no existe';
            }
        }
    }
    
    /**
     * Obtener prioridad de implementación
     */
    private function getPriority($path) {
        if (strpos($path, '/api/') !== false) return 3;
        if (strpos($path, '/dashboard/') !== false) return 2;
        return 1;
    }
    
    /**
     * Crear nuevo usuario
     */
    public function createUser($username, $password, $role = 'User') {
        if (!$this->db) {
            return ['success' => false, 'error' => 'No hay conexión a la base de datos'];
        }
        
        $validRoles = ['SuperUser', 'Admin', 'SupportAdmin', 'User'];
        if (!in_array($role, $validRoles)) {
            return ['success' => false, 'error' => 'Rol inválido'];
        }
        
        try {
            // Verificar si existe
            $stmt = $this->db->prepare("SELECT COUNT(*) as count FROM users WHERE username = ?");
            $stmt->execute([$username]);
            
            if ($stmt->fetch()['count'] > 0) {
                return ['success' => false, 'error' => 'El usuario ya existe'];
            }
            
            // Crear usuario
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $this->db->prepare("
                INSERT INTO users (username, password, role, active, created_at) 
                VALUES (?, ?, ?, 1, NOW())
            ");
            
            $stmt->execute([$username, $passwordHash, $role]);
            
            return [
                'success' => true, 
                'message' => "Usuario '$username' creado exitosamente con rol '$role'"
            ];
            
        } catch (PDOException $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * Test de login
     */
    public function testLogin($username, $password) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "http://localhost/login/login.php");
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([
            'username' => $username,
            'password' => $password
        ]));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($response === false) {
            return ['success' => false, 'error' => 'Error de conexión'];
        }
        
        $data = json_decode($response, true);
        
        return [
            'success' => $httpCode === 200 && isset($data['success']) && $data['success'],
            'http_code' => $httpCode,
            'response' => $data
        ];
    }
    
    /**
     * Generar reporte completo
     */
    private function generateReport() {
        return [
            'timestamp' => date('Y-m-d H:i:s'),
            'system' => 'SKYN3T v3.0',
            'summary' => [
                'total_errors' => count($this->errors),
                'total_warnings' => count($this->warnings),
                'status' => empty($this->errors) ? '✅ Sistema operativo' : '❌ Sistema con errores'
            ],
            'errors' => $this->errors,
            'warnings' => $this->warnings,
            'results' => $this->results
        ];
    }
}

// Procesar solicitudes
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    $action = $_POST['action'] ?? '';
    $diagnostics = new SKYN3TDiagnostics();
    
    switch ($action) {
        case 'create_user':
            $result = $diagnostics->createUser(
                $_POST['username'] ?? '',
                $_POST['password'] ?? '',
                $_POST['role'] ?? 'User'
            );
            echo json_encode($result);
            exit;
            
        case 'test_login':
            $result = $diagnostics->testLogin(
                $_POST['username'] ?? '',
                $_POST['password'] ?? ''
            );
            echo json_encode($result);
            exit;
            
        case 'run_diagnostics':
            $result = $diagnostics->runFullDiagnostics();
            echo json_encode($result);
            exit;
    }
}

// Si es GET, mostrar interfaz
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SKYN3T - Diagnóstico del Sistema</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f0f0f;
            color: #e0e0e0;
            line-height: 1.6;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 2px solid #2199ea;
            border-radius: 15px;
            padding: 30px;
            text-align: center;
            margin-bottom: 30px;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(33, 153, 234, 0.1) 0%, transparent 70%);
            animation: pulse 4s ease-in-out infinite;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 0.5; }
            50% { transform: scale(1.1); opacity: 0.8; }
        }
        
        h1 {
            color: #2199ea;
            font-size: 2.5rem;
            margin-bottom: 10px;
            position: relative;
            z-index: 1;
        }
        
        .subtitle {
            color: #888;
            font-size: 1.1rem;
            position: relative;
            z-index: 1;
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: rgba(55, 65, 79, 0.3);
            border: 1px solid rgba(33, 153, 234, 0.3);
            border-radius: 10px;
            padding: 20px;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
            border-color: #2199ea;
            box-shadow: 0 10px 30px rgba(33, 153, 234, 0.2);
        }
        
        .card-title {
            color: #2199ea;
            font-size: 1.3rem;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .button {
            background: linear-gradient(135deg, #2199ea, #137dc5);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.3s ease;
            margin: 5px;
            display: inline-block;
        }
        
        .button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(33, 153, 234, 0.4);
        }
        
        .button:active {
            transform: translateY(0);
        }
        
        .button.secondary {
            background: linear-gradient(135deg, #6c757d, #495057);
        }
        
        .button.danger {
            background: linear-gradient(135deg, #dc3545, #c82333);
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        label {
            display: block;
            color: #2199ea;
            margin-bottom: 5px;
            font-weight: 500;
        }
        
        input[type="text"],
        input[type="password"],
        select {
            width: 100%;
            padding: 10px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(33, 153, 234, 0.3);
            border-radius: 5px;
            color: #fff;
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        
        input:focus,
        select:focus {
            outline: none;
            border-color: #2199ea;
            background: rgba(255, 255, 255, 0.15);
        }
        
        .results {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid rgba(33, 153, 234, 0.3);
            border-radius: 10px;
            padding: 20px;
            margin-top: 30px;
            max-height: 600px;
            overflow-y: auto;
        }
        
        .results::-webkit-scrollbar {
            width: 10px;
        }
        
        .results::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 5px;
        }
        
        .results::-webkit-scrollbar-thumb {
            background: #2199ea;
            border-radius: 5px;
        }
        
        .error {
            color: #ff6b6b;
            background: rgba(220, 53, 69, 0.1);
            border: 1px solid rgba(220, 53, 69, 0.3);
            padding: 10px;
            border-radius: 5px;
            margin: 5px 0;
        }
        
        .warning {
            color: #ffd93d;
            background: rgba(255, 193, 7, 0.1);
            border: 1px solid rgba(255, 193, 7, 0.3);
            padding: 10px;
            border-radius: 5px;
            margin: 5px 0;
        }
        
        .success {
            color: #51cf66;
            background: rgba(40, 167, 69, 0.1);
            border: 1px solid rgba(40, 167, 69, 0.3);
            padding: 10px;
            border-radius: 5px;
            margin: 5px 0;
        }
        
        pre {
            background: rgba(0, 0, 0, 0.3);
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9rem;
            line-height: 1.4;
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        
        .spinner {
            border: 3px solid rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            border-top: 3px solid #2199ea;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 10px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .icon {
            font-size: 1.5rem;
            vertical-align: middle;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: rgba(33, 153, 234, 0.1);
            border: 1px solid rgba(33, 153, 234, 0.3);
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2rem;
            color: #2199ea;
            font-weight: bold;
        }
        
        .stat-label {
            color: #888;
            font-size: 0.9rem;
            margin-top: 5px;
        }
        
        @media (max-width: 768px) {
            .grid {
                grid-template-columns: 1fr;
            }
            
            h1 {
                font-size: 2rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔧 SKYN3T - Diagnóstico del Sistema</h1>
            <p class="subtitle">Herramienta completa de análisis y verificación v3.0</p>
        </div>
        
        <div class="grid">
            <!-- Diagnóstico General -->
            <div class="card">
                <h2 class="card-title">
                    <span class="icon">🔍</span>
                    Diagnóstico General
                </h2>
                <p style="margin-bottom: 15px;">
                    Análisis completo del sistema: base de datos, archivos, permisos y funcionalidad.
                </p>
                <button class="button" onclick="runDiagnostics()">
                    Ejecutar Diagnóstico Completo
                </button>
                <button class="button secondary" onclick="clearResults()">
                    Limpiar Resultados
                </button>
            </div>
            
            <!-- Crear Usuario -->
            <div class="card">
                <h2 class="card-title">
                    <span class="icon">👤</span>
                    Crear Usuario
                </h2>
                <form id="createUserForm" onsubmit="createUser(event)">
                    <div class="form-group">
                        <label>Nombre de usuario:</label>
                        <input type="text" name="username" required>
                    </div>
                    <div class="form-group">
                        <label>Contraseña:</label>
                        <input type="password" name="password" required>
                    </div>
                    <div class="form-group">
                        <label>Rol:</label>
                        <select name="role">
                            <option value="User">User</option>
                            <option value="SupportAdmin">SupportAdmin</option>
                            <option value="Admin">Admin</option>
                            <option value="SuperUser">SuperUser</option>
                        </select>
                    </div>
                    <button type="submit" class="button">
                        Crear Usuario
                    </button>
                </form>
            </div>
            
            <!-- Test de Login -->
            <div class="card">
                <h2 class="card-title">
                    <span class="icon">🔐</span>
                    Test de Login
                </h2>
                <form id="testLoginForm" onsubmit="testLogin(event)">
                    <div class="form-group">
                        <label>Usuario:</label>
                        <input type="text" name="test_username" required>
                    </div>
                    <div class="form-group">
                        <label>Contraseña:</label>
                        <input type="password" name="test_password" required>
                    </div>
                    <button type="submit" class="button">
                        Probar Login
                    </button>
                </form>
            </div>
        </div>
        
        <!-- Área de resultados -->
        <div id="loading" class="loading">
            <div class="spinner"></div>
            <p>Ejecutando diagnóstico...</p>
        </div>
        
        <div id="results" class="results" style="display: none;">
            <!-- Los resultados se mostrarán aquí -->
        </div>
    </div>
    
    <script>
        // Función para ejecutar diagnóstico completo
        async function runDiagnostics() {
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            
            try {
                const formData = new FormData();
                formData.append('action', 'run_diagnostics');
                
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                displayResults(data);
                
            } catch (error) {
                alert('Error ejecutando diagnóstico: ' + error.message);
            } finally {
                document.getElementById('loading').style.display = 'none';
            }
        }
        
        // Función para mostrar resultados
        function displayResults(data) {
            const resultsDiv = document.getElementById('results');
            resultsDiv.style.display = 'block';
            
            let html = '<h2 style="color: #2199ea; margin-bottom: 20px;">📊 Resultados del Diagnóstico</h2>';
            
            // Resumen
            html += '<div class="stats-grid">';
            html += `<div class="stat-card">
                <div class="stat-value">${data.summary.total_errors}</div>
                <div class="stat-label">Errores</div>
            </div>`;
            html += `<div class="stat-card">
                <div class="stat-value">${data.summary.total_warnings}</div>
                <div class="stat-label">Advertencias</div>
            </div>`;
            html += `<div class="stat-card">
                <div class="stat-value">${data.summary.status}</div>
                <div class="stat-label">Estado</div>
            </div>`;
            html += '</div>';
            
            // Errores
            if (data.errors.length > 0) {
                html += '<h3 style="color: #ff6b6b; margin: 20px 0 10px;">❌ Errores Encontrados</h3>';
                data.errors.forEach(error => {
                    html += `<div class="error">${error}</div>`;
                });
            }
            
            // Advertencias
            if (data.warnings.length > 0) {
                html += '<h3 style="color: #ffd93d; margin: 20px 0 10px;">⚠️ Advertencias</h3>';
                data.warnings.forEach(warning => {
                    html += `<div class="warning">${warning}</div>`;
                });
            }
            
            // Resultados detallados
            html += '<h3 style="color: #2199ea; margin: 20px 0 10px;">📋 Resultados Detallados</h3>';
            html += '<pre>' + JSON.stringify(data.results, null, 2) + '</pre>';
            
            resultsDiv.innerHTML = html;
            resultsDiv.scrollTop = 0;
        }
        
        // Función para crear usuario
        async function createUser(event) {
            event.preventDefault();
            
            const formData = new FormData(event.target);
            formData.append('action', 'create_user');
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.success) {
                    alert('✅ ' + data.message);
                    event.target.reset();
                } else {
                    alert('❌ Error: ' + data.error);
                }
                
            } catch (error) {
                alert('Error creando usuario: ' + error.message);
            }
        }
        
        // Función para test de login
        async function testLogin(event) {
            event.preventDefault();
            
            const formData = new FormData();
            formData.append('action', 'test_login');
            formData.append('username', event.target.test_username.value);
            formData.append('password', event.target.test_password.value);
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.success) {
                    alert('✅ Login exitoso!\n\nRespuesta:\n' + JSON.stringify(data.response, null, 2));
                } else {
                    alert('❌ Login falló\n\nCódigo HTTP: ' + data.http_code + '\nRespuesta: ' + JSON.stringify(data.response, null, 2));
                }
                
            } catch (error) {
                alert('Error en test de login: ' + error.message);
            }
        }
        
        // Función para limpiar resultados
        function clearResults() {
            document.getElementById('results').style.display = 'none';
            document.getElementById('results').innerHTML = '';
        }
        
        // Auto-ejecutar diagnóstico al cargar
        window.addEventListener('load', function() {
            // Opcional: ejecutar diagnóstico automáticamente
            // runDiagnostics();
        });
    </script>
</body>
</html>
