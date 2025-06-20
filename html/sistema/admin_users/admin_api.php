<?php
/**
 * API de Administración Total del Sistema SKYN3T
 * Acceso EXCLUSIVO para peterh4ck - Control total de BD y usuarios
 * Versión: 3.0.1 - Plataforma de Administración Completa
 */

session_start();

// Incluir archivos necesarios
require_once __DIR__ . '/../includes/database.php';
require_once __DIR__ . '/../includes/config.php';

header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');

// Verificar acceso EXCLUSIVO para peterh4ck
function checkAdminAccess() {
    if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
        http_response_code(401);
        echo json_encode(['error' => 'No autorizado - Sesión no válida']);
        exit;
    }

    // Verificar tiempo de sesión
    if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > 28800) {
        session_destroy();
        http_response_code(401);
        echo json_encode(['error' => 'Sesión expirada']);
        exit;
    }

    // VERIFICACIÓN ESTRICTA: Solo peterh4ck
    $username = $_SESSION['username'] ?? '';
    $role = $_SESSION['role'] ?? 'User';

    if ($username !== 'peterh4ck') {
        http_response_code(403);
        echo json_encode([
            'error' => 'Acceso DENEGADO - Área exclusiva para administrador principal',
            'attempted_user' => $username,
            'required_user' => 'peterh4ck'
        ]);
        
        // Log de seguridad
        error_log("UNAUTHORIZED ADMIN API ACCESS: user=$username, ip=" . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        exit;
    }

    if ($role !== 'SuperUser') {
        http_response_code(403);
        echo json_encode([
            'error' => 'Permisos insuficientes - Se requiere rol SuperUser',
            'current_role' => $role,
            'required_role' => 'SuperUser'
        ]);
        exit;
    }

    return $username;
}

// Verificar acceso antes de procesar
$adminUser = checkAdminAccess();

$action = $_GET['action'] ?? '';

try {
    // Obtener instancia de base de datos
    $db = Database::getInstance();

    switch($action) {
        case 'quick_stats':
            getQuickStats($db);
            break;
        case 'list_users':
            listUsers($db);
            break;
        case 'get_user':
            getUser($db);
            break;
        case 'create_user':
            createUser($db);
            break;
        case 'update_user':
            updateUser($db);
            break;
        case 'delete_user':
            deleteUser($db);
            break;
        case 'list_roles':
            listRoles($db);
            break;
        case 'update_permissions':
            updatePermissions($db);
            break;
        case 'list_tables':
            listTables($db);
            break;
        case 'table_structure':
            getTableStructure($db);
            break;
        case 'execute_sql':
            executeSQL($db);
            break;
        case 'backup_database':
            backupDatabase($db);
            break;
        case 'security_logs':
            getSecurityLogs($db);
            break;
        case 'active_sessions':
            getActiveSessions($db);
            break;
        case 'system_info':
            getSystemInfo($db);
            break;
        case 'maintenance_mode':
            toggleMaintenanceMode($db);
            break;
        case 'emergency_actions':
            emergencyActions($db);
            break;
        default:
            http_response_code(400);
            echo json_encode([
                'error' => 'Acción no válida',
                'available_actions' => [
                    'quick_stats', 'list_users', 'get_user', 'create_user', 'update_user', 'delete_user',
                    'list_roles', 'update_permissions', 'list_tables', 'table_structure', 'execute_sql',
                    'backup_database', 'security_logs', 'active_sessions', 'system_info', 
                    'maintenance_mode', 'emergency_actions'
                ]
            ]);
    }
} catch (Exception $e) {
    error_log("Error en admin_api.php: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Error interno del servidor',
        'message' => $e->getMessage(),
        'debug' => DEBUG_MODE ? $e->getTraceAsString() : null
    ]);
}

// Obtener estadísticas rápidas del sistema
function getQuickStats($db) {
    try {
        $stats = [];

        // Total de usuarios
        $stmt = $db->execute("SELECT COUNT(*) as count FROM users");
        $stats['total_users'] = $stmt->fetch()['count'];

        // Usuarios activos
        $stmt = $db->execute("SELECT COUNT(*) as count FROM users WHERE active = 1");
        $stats['active_users'] = $stmt->fetch()['count'];

        // Administradores (Admin y SuperUser)
        $stmt = $db->execute("SELECT COUNT(*) as count FROM users WHERE role IN ('Admin', 'SuperUser')");
        $stats['admin_users'] = $stmt->fetch()['count'];

        // Total de tablas en la BD
        $stmt = $db->execute("SHOW TABLES");
        $stats['total_tables'] = count($stmt->fetchAll());

        // Sesiones activas
        $stmt = $db->execute("SELECT COUNT(*) as count FROM sessions WHERE expires_at > NOW()");
        $stats['active_sessions'] = $stmt->fetch()['count'];

        // Residentes registrados
        if ($db->tableExists('residentes')) {
            $stmt = $db->execute("SELECT COUNT(*) as count FROM residentes");
            $stats['total_residents'] = $stmt->fetch()['count'];
        } else {
            $stats['total_residents'] = 0;
        }

        // Dispositivos activos
        if ($db->tableExists('devices')) {
            $stmt = $db->execute("SELECT COUNT(*) as count FROM devices WHERE status = 'active'");
            $stats['active_devices'] = $stmt->fetch()['count'];
        } else {
            $stats['active_devices'] = 0;
        }

        // Logs de acceso (últimas 24h)
        if ($db->tableExists('access_log')) {
            $stmt = $db->execute("SELECT COUNT(*) as count FROM access_log WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
            $stats['recent_logs'] = $stmt->fetch()['count'];
        } else {
            $stats['recent_logs'] = 0;
        }

        echo json_encode([
            'success' => true,
            'stats' => $stats,
            'generated_at' => date('Y-m-d H:i:s')
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al obtener estadísticas: ' . $e->getMessage()
        ]);
    }
}

// Listar todos los usuarios
function listUsers($db) {
    try {
        $limit = min((int)($_GET['limit'] ?? 100), 500);
        $offset = (int)($_GET['offset'] ?? 0);
        $search = $_GET['search'] ?? '';

        $where = "WHERE 1=1";
        $params = [];

        if ($search) {
            $where .= " AND (username LIKE ? OR role LIKE ?)";
            $searchTerm = "%$search%";
            $params = [$searchTerm, $searchTerm];
        }

        $sql = "SELECT id, username, role, active, created_at, last_login, 
                       privileges, login_attempts, locked_until
                FROM users
                $where
                ORDER BY 
                    CASE WHEN username = 'peterh4ck' THEN 0 ELSE 1 END,
                    role DESC,
                    created_at DESC
                LIMIT ? OFFSET ?";

        $params[] = $limit;
        $params[] = $offset;

        $stmt = $db->execute($sql, $params);
        $users = $stmt->fetchAll();

        // Contar total para paginación
        $countSql = "SELECT COUNT(*) as total FROM users $where";
        $countParams = array_slice($params, 0, -2);
        $stmt = $db->execute($countSql, $countParams);
        $total = $stmt->fetch()['total'];

        echo json_encode([
            'success' => true,
            'users' => $users,
            'total' => (int)$total,
            'limit' => $limit,
            'offset' => $offset
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al listar usuarios: ' . $e->getMessage()
        ]);
    }
}

// Obtener usuario específico
function getUser($db) {
    try {
        $userId = (int)($_GET['id'] ?? 0);
        if (!$userId) {
            http_response_code(400);
            echo json_encode(['error' => 'ID de usuario requerido']);
            return;
        }

        $stmt = $db->execute(
            "SELECT * FROM users WHERE id = ?",
            [$userId]
        );

        $user = $stmt->fetch();

        if (!$user) {
            http_response_code(404);
            echo json_encode(['error' => 'Usuario no encontrado']);
            return;
        }

        // Obtener sesiones activas del usuario
        $stmt = $db->execute(
            "SELECT * FROM sessions WHERE user_id = ? AND expires_at > NOW() ORDER BY created_at DESC",
            [$userId]
        );
        $sessions = $stmt->fetchAll();

        // Obtener logs recientes del usuario
        if ($db->tableExists('access_log')) {
            $stmt = $db->execute(
                "SELECT * FROM access_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10",
                [$userId]
            );
            $logs = $stmt->fetchAll();
        } else {
            $logs = [];
        }

        echo json_encode([
            'success' => true,
            'user' => $user,
            'active_sessions' => $sessions,
            'recent_logs' => $logs
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al obtener usuario: ' . $e->getMessage()
        ]);
    }
}

// Crear nuevo usuario
function createUser($db) {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'Método no permitido']);
        return;
    }

    try {
        $data = json_decode(file_get_contents('php://input'), true);

        // Validar datos requeridos
        $required = ['username', 'password', 'role'];
        foreach ($required as $field) {
            if (empty($data[$field])) {
                http_response_code(400);
                echo json_encode(['error' => "Campo requerido: $field"]);
                return;
            }
        }

        // Verificar que el usuario no existe
        $stmt = $db->execute("SELECT id FROM users WHERE username = ?", [$data['username']]);
        if ($stmt->fetch()) {
            http_response_code(400);
            echo json_encode(['error' => 'El nombre de usuario ya existe']);
            return;
        }

        // Roles válidos
        $validRoles = ['User', 'SupportAdmin', 'Admin', 'SuperUser'];
        if (!in_array($data['role'], $validRoles)) {
            http_response_code(400);
            echo json_encode(['error' => 'Rol no válido', 'valid_roles' => $validRoles]);
            return;
        }

        $db->beginTransaction();

        // Hash de la contraseña
        $hashedPassword = password_hash($data['password'], PASSWORD_DEFAULT);

        // Permisos por defecto según el rol
        $defaultPermissions = [
            'User' => ['dashboard' => true, 'relay' => true],
            'SupportAdmin' => ['dashboard' => true, 'devices' => true, 'relay' => true, 'logs' => true],
            'Admin' => ['dashboard' => true, 'devices' => true, 'users' => true, 'relay' => true, 'logs' => true],
            'SuperUser' => ['all' => true, 'dashboard' => true, 'devices' => true, 'users' => true, 'relay' => true, 'logs' => true, 'system' => true]
        ];

        // Insertar usuario
        $sql = "INSERT INTO users (username, password, role, active, privileges, created_at)
                VALUES (?, ?, ?, ?, ?, NOW())";

        $params = [
            $data['username'],
            $hashedPassword,
            $data['role'],
            isset($data['active']) ? (int)(bool)$data['active'] : 1,
            json_encode($defaultPermissions[$data['role']])
        ];

        $stmt = $db->execute($sql, $params);
        $userId = $db->lastInsertId();

        // Registrar en logs
        if ($db->tableExists('access_log')) {
            $db->execute(
                "INSERT INTO access_log (user_id, username, action, ip_address, user_agent, timestamp)
                 VALUES (?, ?, 'user_created_by_admin', ?, ?, NOW())",
                [
                    $_SESSION['user_id'],
                    $_SESSION['username'],
                    $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                    $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
                ]
            );
        }

        $db->commit();

        echo json_encode([
            'success' => true,
            'message' => 'Usuario creado exitosamente',
            'user_id' => $userId,
            'username' => $data['username'],
            'role' => $data['role']
        ]);

    } catch (Exception $e) {
        $db->rollback();
        error_log("Error creando usuario: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Error al crear usuario: ' . $e->getMessage()]);
    }
}

// Actualizar usuario
function updateUser($db) {
    if ($_SERVER['REQUEST_METHOD'] !== 'PUT') {
        http_response_code(405);
        echo json_encode(['error' => 'Método no permitido']);
        return;
    }

    try {
        $userId = (int)($_GET['id'] ?? 0);
        if (!$userId) {
            http_response_code(400);
            echo json_encode(['error' => 'ID de usuario requerido']);
            return;
        }

        $data = json_decode(file_get_contents('php://input'), true);

        // Verificar que el usuario existe
        $stmt = $db->execute("SELECT * FROM users WHERE id = ?", [$userId]);
        $currentUser = $stmt->fetch();

        if (!$currentUser) {
            http_response_code(404);
            echo json_encode(['error' => 'Usuario no encontrado']);
            return;
        }

        // Proteger cuenta de peterh4ck
        if ($currentUser['username'] === 'peterh4ck' && $_SESSION['username'] !== 'peterh4ck') {
            http_response_code(403);
            echo json_encode(['error' => 'No se puede modificar la cuenta del administrador principal']);
            return;
        }

        $db->beginTransaction();

        $updateFields = [];
        $params = [];

        // Actualizar campos permitidos
        if (isset($data['role']) && $data['role'] !== $currentUser['role']) {
            $validRoles = ['User', 'SupportAdmin', 'Admin', 'SuperUser'];
            if (in_array($data['role'], $validRoles)) {
                $updateFields[] = "role = ?";
                $params[] = $data['role'];
            }
        }

        if (isset($data['active']) && (bool)$data['active'] !== (bool)$currentUser['active']) {
            $updateFields[] = "active = ?";
            $params[] = (int)(bool)$data['active'];
        }

        if (isset($data['password']) && !empty($data['password'])) {
            $updateFields[] = "password = ?";
            $params[] = password_hash($data['password'], PASSWORD_DEFAULT);
        }

        if (isset($data['privileges'])) {
            $updateFields[] = "privileges = ?";
            $params[] = json_encode($data['privileges']);
        }

        if (!empty($updateFields)) {
            $updateFields[] = "updated_at = NOW()";
            $params[] = $userId;

            $sql = "UPDATE users SET " . implode(", ", $updateFields) . " WHERE id = ?";
            $db->execute($sql, $params);

            // Registrar en logs
            if ($db->tableExists('access_log')) {
                $db->execute(
                    "INSERT INTO access_log (user_id, username, action, ip_address, user_agent, timestamp)
                     VALUES (?, ?, 'user_updated_by_admin', ?, ?, NOW())",
                    [
                        $_SESSION['user_id'],
                        $_SESSION['username'],
                        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                        $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
                    ]
                );
            }
        }

        $db->commit();

        echo json_encode([
            'success' => true,
            'message' => 'Usuario actualizado exitosamente'
        ]);

    } catch (Exception $e) {
        $db->rollback();
        error_log("Error actualizando usuario: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Error al actualizar usuario: ' . $e->getMessage()]);
    }
}

// Eliminar usuario
function deleteUser($db) {
    if ($_SERVER['REQUEST_METHOD'] !== 'DELETE') {
        http_response_code(405);
        echo json_encode(['error' => 'Método no permitido']);
        return;
    }

    try {
        $userId = (int)($_GET['id'] ?? 0);
        if (!$userId) {
            http_response_code(400);
            echo json_encode(['error' => 'ID de usuario requerido']);
            return;
        }

        $stmt = $db->execute("SELECT * FROM users WHERE id = ?", [$userId]);
        $user = $stmt->fetch();

        if (!$user) {
            http_response_code(404);
            echo json_encode(['error' => 'Usuario no encontrado']);
            return;
        }

        // No se puede eliminar a peterh4ck
        if ($user['username'] === 'peterh4ck') {
            http_response_code(403);
            echo json_encode(['error' => 'No se puede eliminar la cuenta del administrador principal']);
            return;
        }

        $db->beginTransaction();

        // Eliminar sesiones del usuario
        $db->execute("DELETE FROM sessions WHERE user_id = ?", [$userId]);

        // Registrar en logs antes de eliminar
        if ($db->tableExists('access_log')) {
            $db->execute(
                "INSERT INTO access_log (user_id, username, action, ip_address, user_agent, timestamp)
                 VALUES (?, ?, 'user_deleted_by_admin', ?, ?, NOW())",
                [
                    $_SESSION['user_id'],
                    $_SESSION['username'],
                    $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                    $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
                ]
            );
        }

        // Eliminar usuario
        $db->execute("DELETE FROM users WHERE id = ?", [$userId]);

        $db->commit();

        echo json_encode([
            'success' => true,
            'message' => 'Usuario eliminado exitosamente',
            'deleted_user' => $user['username']
        ]);

    } catch (Exception $e) {
        $db->rollback();
        error_log("Error eliminando usuario: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Error al eliminar usuario: ' . $e->getMessage()]);
    }
}

// Listar roles disponibles
function listRoles($db) {
    try {
        $roles = [
            'User' => [
                'name' => 'Usuario',
                'description' => 'Acceso básico al sistema',
                'permissions' => ['dashboard', 'relay']
            ],
            'SupportAdmin' => [
                'name' => 'Administrador de Soporte',
                'description' => 'Acceso a soporte y visualización',
                'permissions' => ['dashboard', 'devices', 'relay', 'logs']
            ],
            'Admin' => [
                'name' => 'Administrador',
                'description' => 'Gestión de dispositivos y usuarios',
                'permissions' => ['dashboard', 'devices', 'users', 'relay', 'logs']
            ],
            'SuperUser' => [
                'name' => 'Super Usuario',
                'description' => 'Acceso total al sistema',
                'permissions' => ['all', 'dashboard', 'devices', 'users', 'relay', 'logs', 'system']
            ]
        ];

        // Contar usuarios por rol
        foreach ($roles as $role => &$info) {
            $stmt = $db->execute("SELECT COUNT(*) as count FROM users WHERE role = ?", [$role]);
            $info['user_count'] = $stmt->fetch()['count'];
        }

        echo json_encode([
            'success' => true,
            'roles' => $roles
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al obtener roles: ' . $e->getMessage()
        ]);
    }
}

// Listar tablas de la base de datos
function listTables($db) {
    try {
        $stmt = $db->execute("SHOW TABLES");
        $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);

        $tableInfo = [];
        foreach ($tables as $table) {
            // Obtener información de cada tabla
            $stmt = $db->execute("SELECT COUNT(*) as row_count FROM `$table`");
            $rowCount = $stmt->fetch()['row_count'];

            $stmt = $db->execute("SHOW CREATE TABLE `$table`");
            $createInfo = $stmt->fetch();

            $tableInfo[] = [
                'name' => $table,
                'row_count' => (int)$rowCount,
                'engine' => 'InnoDB', // Por defecto
                'size' => 'N/A' // Calculado después si es necesario
            ];
        }

        echo json_encode([
            'success' => true,
            'tables' => $tableInfo,
            'total_tables' => count($tables)
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al listar tablas: ' . $e->getMessage()
        ]);
    }
}

// Obtener estructura de tabla
function getTableStructure($db) {
    try {
        $table = $_GET['table'] ?? '';
        if (empty($table)) {
            http_response_code(400);
            echo json_encode(['error' => 'Nombre de tabla requerido']);
            return;
        }

        // Validar que la tabla existe
        $stmt = $db->execute("SHOW TABLES LIKE ?", [$table]);
        if (!$stmt->fetch()) {
            http_response_code(404);
            echo json_encode(['error' => 'Tabla no encontrada']);
            return;
        }

        // Obtener estructura
        $stmt = $db->execute("DESCRIBE `$table`");
        $columns = $stmt->fetchAll();

        // Obtener índices
        $stmt = $db->execute("SHOW INDEX FROM `$table`");
        $indexes = $stmt->fetchAll();

        echo json_encode([
            'success' => true,
            'table' => $table,
            'columns' => $columns,
            'indexes' => $indexes
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al obtener estructura: ' . $e->getMessage()
        ]);
    }
}

// Ejecutar SQL (¡PELIGROSO! Solo para peterh4ck)
function executeSQL($db) {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'Método no permitido']);
        return;
    }

    try {
        $data = json_decode(file_get_contents('php://input'), true);
        $sql = $data['sql'] ?? '';

        if (empty($sql)) {
            http_response_code(400);
            echo json_encode(['error' => 'SQL requerido']);
            return;
        }

        // Log de seguridad
        error_log("SQL EXECUTION by peterh4ck: " . $sql);

        $result = $db->execute($sql);
        
        if (stripos($sql, 'SELECT') === 0) {
            $data = $result->fetchAll();
            echo json_encode([
                'success' => true,
                'type' => 'select',
                'data' => $data,
                'row_count' => count($data)
            ]);
        } else {
            echo json_encode([
                'success' => true,
                'type' => 'query',
                'affected_rows' => $result->rowCount(),
                'message' => 'Query ejecutado exitosamente'
            ]);
        }

    } catch (Exception $e) {
        error_log("SQL EXECUTION ERROR: " . $e->getMessage());
        echo json_encode([
            'success' => false,
            'error' => 'Error ejecutando SQL: ' . $e->getMessage()
        ]);
    }
}

// Obtener sesiones activas
function getActiveSessions($db) {
    try {
        $sql = "SELECT s.*, u.username, u.role 
                FROM sessions s 
                JOIN users u ON s.user_id = u.id 
                WHERE s.expires_at > NOW() 
                ORDER BY s.last_activity DESC";

        $stmt = $db->execute($sql);
        $sessions = $stmt->fetchAll();

        echo json_encode([
            'success' => true,
            'sessions' => $sessions,
            'total' => count($sessions)
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al obtener sesiones: ' . $e->getMessage()
        ]);
    }
}

// Obtener información del sistema
function getSystemInfo($db) {
    try {
        $info = [
            'php_version' => PHP_VERSION,
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
            'database_version' => $db->execute("SELECT VERSION() as version")->fetch()['version'],
            'server_time' => date('Y-m-d H:i:s'),
            'server_timezone' => date_default_timezone_get(),
            'memory_usage' => memory_get_usage(true),
            'memory_peak' => memory_get_peak_usage(true),
            'disk_free_space' => disk_free_space('.'),
            'disk_total_space' => disk_total_space('.'),
            'load_average' => sys_getloadavg()
        ];

        echo json_encode([
            'success' => true,
            'system_info' => $info
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al obtener información del sistema: ' . $e->getMessage()
        ]);
    }
}

// Funciones adicionales (básicas por ahora)
function updatePermissions($db) {
    echo json_encode([
        'success' => false,
        'error' => 'Función de actualización de permisos en desarrollo'
    ]);
}

function backupDatabase($db) {
    echo json_encode([
        'success' => false,
        'error' => 'Función de backup en desarrollo'
    ]);
}

function getSecurityLogs($db) {
    echo json_encode([
        'success' => false,
        'error' => 'Función de logs de seguridad en desarrollo'
    ]);
}

function toggleMaintenanceMode($db) {
    echo json_encode([
        'success' => false,
        'error' => 'Función de modo mantenimiento en desarrollo'
    ]);
}

function emergencyActions($db) {
    echo json_encode([
        'success' => false,
        'error' => 'Funciones de emergencia en desarrollo'
    ]);
}
?>