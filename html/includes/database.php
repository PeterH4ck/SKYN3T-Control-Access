<?php
/**
 * SKYN3T - Sistema de Control y Monitoreo
 * Gestión de base de datos
 * 
 * @version 2.0.0
 * @date 2025-01-19
 */

// Incluir configuración
require_once __DIR__ . '/config.php';

/**
 * Clase Singleton para manejo de base de datos
 */
class Database {
    private static $instance = null;
    private $connection = null;
    private $last_error = null;
    
    /**
     * Constructor privado (patrón Singleton)
     */
    private function __construct() {
        $this->connect();
    }
    
    /**
     * Obtener instancia única
     */
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Establecer conexión a la base de datos
     */
    private function connect() {
        try {
            $config = get_db_config();
            
            $dsn = "mysql:host={$config['host']};dbname={$config['dbname']};charset={$config['charset']}";
            
            $this->connection = new PDO($dsn, $config['username'], $config['password'], $config['options']);
            
            // Log de conexión exitosa
            if (LOG_DEBUG) {
                debug_log('Database connection established');
            }
            
        } catch (PDOException $e) {
            $this->last_error = $e->getMessage();
            
            // Log de error
            if (LOG_ERRORS) {
                error_log("Database connection error: " . $e->getMessage(), 3, LOG_PATH . '/error.log');
            }
            
            // En desarrollo mostrar error, en producción error genérico
            if (DEBUG_MODE) {
                throw new Exception("Database connection failed: " . $e->getMessage());
            } else {
                throw new Exception("Database connection failed");
            }
        }
    }
    
    /**
     * Obtener conexión PDO
     */
    public function getConnection() {
        if ($this->connection === null) {
            $this->connect();
        }
        return $this->connection;
    }
    
    /**
     * Ejecutar query con prepared statement
     */
    public function execute($sql, $params = []) {
        try {
            $stmt = $this->connection->prepare($sql);
            $result = $stmt->execute($params);
            
            if (!$result) {
                throw new Exception("Query execution failed");
            }
            
            return $stmt;
            
        } catch (Exception $e) {
            $this->last_error = $e->getMessage();
            
            if (LOG_ERRORS) {
                error_log("Query error: " . $e->getMessage() . " - SQL: " . $sql, 3, LOG_PATH . '/error.log');
            }
            
            throw $e;
        }
    }
    
    /**
     * Obtener último error
     */
    public function getLastError() {
        return $this->last_error;
    }
    
    /**
     * Verificar conexión
     */
    public function isConnected() {
        try {
            if ($this->connection === null) {
                return false;
            }
            
            $this->connection->query('SELECT 1');
            return true;
            
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Obtener información de la base de datos
     */
    public function getDatabaseInfo() {
        try {
            $info = [
                'version' => $this->connection->getAttribute(PDO::ATTR_SERVER_VERSION),
                'database' => DB_NAME,
                'connection_status' => 'connected',
                'tables_count' => 0
            ];
            
            // Contar tablas
            $stmt = $this->execute("SELECT COUNT(*) as count FROM information_schema.tables WHERE table_schema = ?", [DB_NAME]);
            $result = $stmt->fetch();
            $info['tables_count'] = $result['count'];
            
            return $info;
            
        } catch (Exception $e) {
            return [
                'error' => $e->getMessage(),
                'connection_status' => 'error'
            ];
        }
    }
    
    /**
     * Verificar si una tabla existe
     */
    public function tableExists($table_name) {
        try {
            $stmt = $this->execute(
                "SELECT COUNT(*) as count FROM information_schema.tables WHERE table_schema = ? AND table_name = ?",
                [DB_NAME, $table_name]
            );
            $result = $stmt->fetch();
            return $result['count'] > 0;
            
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Obtener estructura de una tabla
     */
    public function getTableStructure($table_name) {
        try {
            $stmt = $this->execute("DESCRIBE $table_name");
            return $stmt->fetchAll();
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Iniciar transacción
     */
    public function beginTransaction() {
        return $this->connection->beginTransaction();
    }
    
    /**
     * Confirmar transacción
     */
    public function commit() {
        return $this->connection->commit();
    }
    
    /**
     * Revertir transacción
     */
    public function rollback() {
        return $this->connection->rollBack();
    }
    
    /**
     * Obtener último ID insertado
     */
    public function lastInsertId() {
        return $this->connection->lastInsertId();
    }
    
    /**
     * Cerrar conexión
     */
    public function close() {
        $this->connection = null;
    }
    
    /**
     * Prevenir clonación
     */
    private function __clone() {}
    
    /**
     * Prevenir deserialización
     */
    public function __wakeup() {
        throw new Exception("Cannot unserialize singleton");
    }
}

// ===========================
// FUNCIONES HELPER
// ===========================

/**
 * Obtener estado actual del relé
 */
function get_relay_status() {
    try {
        $db = Database::getInstance();
        $stmt = $db->execute(
            "SELECT * FROM " . TABLE_RELAY_STATUS . " ORDER BY timestamp DESC LIMIT 1"
        );
        
        $status = $stmt->fetch();
        
        if (!$status) {
            // Si no hay registros, crear uno inicial
            $stmt = $db->execute(
                "INSERT INTO " . TABLE_RELAY_STATUS . " (relay_state, led_state, changed_by, change_method, timestamp) VALUES (?, ?, ?, ?, NOW())",
                [RELAY_STATE_OFF, LED_STATE_OFF, 0, 'system']
            );
            
            return [
                'relay_state' => RELAY_STATE_OFF,
                'led_state' => LED_STATE_OFF,
                'changed_by' => 0,
                'change_method' => 'system',
                'timestamp' => date('Y-m-d H:i:s')
            ];
        }
        
        return $status;
        
    } catch (Exception $e) {
        error_log("Error getting relay status: " . $e->getMessage());
        return false;
    }
}

/**
 * Actualizar estado del relé
 */
function update_relay_status($relay_state, $led_state, $user_id, $change_method = 'web') {
    try {
        $db = Database::getInstance();
        
        // Insertar nuevo registro (histórico)
        $stmt = $db->execute(
            "INSERT INTO " . TABLE_RELAY_STATUS . " (relay_state, led_state, changed_by, change_method, timestamp) VALUES (?, ?, ?, ?, NOW())",
            [$relay_state, $led_state, $user_id, $change_method]
        );
        
        // Log de actividad
        log_activity('relay_change', $user_id, [
            'relay_state' => $relay_state,
            'led_state' => $led_state,
            'method' => $change_method
        ]);
        
        return true;
        
    } catch (Exception $e) {
        error_log("Error updating relay status: " . $e->getMessage());
        return false;
    }
}

/**
 * Registrar actividad
 */
function log_activity($action, $user_id = null, $details = []) {
    try {
        $db = Database::getInstance();
        
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        
        // Verificar qué columnas existen en la tabla
        $stmt = $db->execute("SHOW COLUMNS FROM " . TABLE_ACCESS_LOG);
        $columns = $stmt->fetchAll();
        $columnNames = array_column($columns, 'Field');
        
        // Determinar qué columnas usar
        $hasCreatedAt = in_array('created_at', $columnNames);
        $hasTimestamp = in_array('timestamp', $columnNames);
        $hasDetails = in_array('details', $columnNames);
        
        if ($hasCreatedAt) {
            if ($hasDetails) {
                $stmt = $db->execute(
                    "INSERT INTO " . TABLE_ACCESS_LOG . " (action, user_id, ip_address, user_agent, details, created_at) VALUES (?, ?, ?, ?, ?, NOW())",
                    [$action, $user_id, $ip_address, $user_agent, json_encode($details)]
                );
            } else {
                $stmt = $db->execute(
                    "INSERT INTO " . TABLE_ACCESS_LOG . " (action, user_id, ip_address, user_agent, created_at) VALUES (?, ?, ?, ?, NOW())",
                    [$action, $user_id, $ip_address, $user_agent]
                );
            }
        } elseif ($hasTimestamp) {
            if ($hasDetails) {
                $stmt = $db->execute(
                    "INSERT INTO " . TABLE_ACCESS_LOG . " (action, user_id, ip_address, user_agent, details, timestamp) VALUES (?, ?, ?, ?, ?, NOW())",
                    [$action, $user_id, $ip_address, $user_agent, json_encode($details)]
                );
            } else {
                $stmt = $db->execute(
                    "INSERT INTO " . TABLE_ACCESS_LOG . " (action, user_id, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, NOW())",
                    [$action, $user_id, $ip_address, $user_agent]
                );
            }
        } else {
            // Si no hay columna de fecha, intentar insertar sin ella
            if ($hasDetails) {
                $stmt = $db->execute(
                    "INSERT INTO " . TABLE_ACCESS_LOG . " (action, user_id, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)",
                    [$action, $user_id, $ip_address, $user_agent, json_encode($details)]
                );
            } else {
                $stmt = $db->execute(
                    "INSERT INTO " . TABLE_ACCESS_LOG . " (action, user_id, ip_address, user_agent) VALUES (?, ?, ?, ?)",
                    [$action, $user_id, $ip_address, $user_agent]
                );
            }
        }
        
        return true;
        
    } catch (Exception $e) {
        error_log("Error logging activity: " . $e->getMessage());
        return false;
    }
}

/**
 * Limpiar logs antiguos
 */
function cleanup_old_logs($days = 30) {
    try {
        $db = Database::getInstance();
        
        $stmt = $db->execute(
            "DELETE FROM " . TABLE_ACCESS_LOG . " WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)",
            [$days]
        );
        
        $deleted = $stmt->rowCount();
        
        if (LOG_DEBUG) {
            debug_log("Cleaned up $deleted old log entries");
        }
        
        return $deleted;
        
    } catch (Exception $e) {
        error_log("Error cleaning logs: " . $e->getMessage());
        return false;
    }
}

// ===========================
// ENDPOINT PARA PRUEBAS
// ===========================

// Si se accede directamente vía POST, ejecutar prueba de conexión
if ($_SERVER['REQUEST_METHOD'] === 'POST' && php_sapi_name() !== 'cli') {
    header('Content-Type: application/json');
    
    $input = json_decode(file_get_contents('php://input'), true);
    $action = $input['action'] ?? '';
    
    if ($action === 'test_connection') {
        try {
            $db = Database::getInstance();
            $info = $db->getDatabaseInfo();
            
            echo json_encode([
                'success' => true,
                'database_info' => $info
            ]);
            
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
        exit;
    }
}

// ===========================
// FUNCIONES DE MIGRACIÓN
// ===========================

/**
 * Verificar y crear tablas necesarias
 */
function ensure_tables_exist() {
    $db = Database::getInstance();
    $missing_tables = [];
    
    $required_tables = [
        TABLE_USERS,
        TABLE_SESSIONS,
        TABLE_ACCESS_LOG,
        TABLE_DEVICES,
        TABLE_RELAY_STATUS,
        TABLE_NOTIFICATIONS
    ];
    
    foreach ($required_tables as $table) {
        if (!$db->tableExists($table)) {
            $missing_tables[] = $table;
        }
    }
    
    return $missing_tables;
}

/**
 * Obtener estadísticas de la base de datos
 */
function get_database_stats() {
    try {
        $db = Database::getInstance();
        $stats = [];
        
        // Usuarios
        $stmt = $db->execute("SELECT COUNT(*) as count FROM " . TABLE_USERS);
        $stats['total_users'] = $stmt->fetch()['count'];
        
        // Sesiones activas
        $stmt = $db->execute("SELECT COUNT(*) as count FROM " . TABLE_SESSIONS . " WHERE is_active = 1");
        $stats['active_sessions'] = $stmt->fetch()['count'];
        
        // Dispositivos
        $stmt = $db->execute("SELECT COUNT(*) as count FROM " . TABLE_DEVICES);
        $stats['total_devices'] = $stmt->fetch()['count'];
        
        // Logs del día
        $stmt = $db->execute("SELECT COUNT(*) as count FROM " . TABLE_ACCESS_LOG . " WHERE DATE(created_at) = CURDATE()");
        $stats['logs_today'] = $stmt->fetch()['count'];
        
        // Estado del relé
        $relay_status = get_relay_status();
        $stats['relay_state'] = $relay_status ? ($relay_status['relay_state'] ? 'ON' : 'OFF') : 'Unknown';
        
        return $stats;
        
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}
?>
