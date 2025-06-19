<?php
/**
 * Archivo: /var/www/html/includes/database.php
 * Configuración de base de datos para SKYN3T System
 * Compatible con MariaDB/MySQL
 */

// Definir constante del sistema
if (!defined('SKYN3T_SYSTEM')) {
    define('SKYN3T_SYSTEM', true);
}

// Incluir configuración
require_once __DIR__ . '/config.php';

class Database {
    private static $instance = null;
    private $connection;
    private $host = DB_HOST;
    private $db_name = DB_NAME;
    private $username = DB_USER;
    private $password = DB_PASS;

    /**
     * Constructor privado para Singleton
     */
    private function __construct() {
        $this->connect();
    }

    /**
     * Obtener instancia única de la base de datos (Singleton)
     */
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Establecer conexión con la base de datos
     */
    private function connect() {
        try {
            $dsn = "mysql:host={$this->host};dbname={$this->db_name};charset=" . DB_CHARSET;
            
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES " . DB_CHARSET,
                PDO::ATTR_PERSISTENT => false,
                PDO::ATTR_TIMEOUT => 30
            ];

            $this->connection = new PDO($dsn, $this->username, $this->password, $options);
            
            // Configurar zona horaria
            $this->connection->exec("SET time_zone = '+00:00'");
            
        } catch (PDOException $e) {
            error_log("Error de conexión a base de datos: " . $e->getMessage());
            
            // En producción, no mostrar detalles del error
            if (defined('ENVIRONMENT') && ENVIRONMENT === 'production') {
                throw new Exception('Error de conexión a la base de datos');
            } else {
                throw new Exception('Error de conexión: ' . $e->getMessage());
            }
        }
    }

    /**
     * Obtener conexión PDO
     */
    public function getConnection() {
        // Verificar si la conexión sigue activa
        if (!$this->isConnected()) {
            $this->connect();
        }
        return $this->connection;
    }

    /**
     * Verificar si la conexión está activa
     */
    private function isConnected() {
        try {
            $this->connection->query('SELECT 1');
            return true;
        } catch (PDOException $e) {
            return false;
        }
    }

    /**
     * Cerrar conexión
     */
    public function close() {
        $this->connection = null;
    }

    /**
     * Ejecutar query preparado de forma segura
     */
    public function executeQuery($sql, $params = []) {
        try {
            $stmt = $this->connection->prepare($sql);
            $stmt->execute($params);
            return $stmt;
        } catch (PDOException $e) {
            error_log("Error ejecutando query: " . $e->getMessage() . " | SQL: " . $sql);
            throw new Exception('Error en consulta a la base de datos');
        }
    }

    /**
     * Obtener un registro
     */
    public function fetch($sql, $params = []) {
        $stmt = $this->executeQuery($sql, $params);
        return $stmt->fetch();
    }

    /**
     * Obtener múltiples registros
     */
    public function fetchAll($sql, $params = []) {
        $stmt = $this->executeQuery($sql, $params);
        return $stmt->fetchAll();
    }

    /**
     * Insertar registro y obtener ID
     */
    public function insert($sql, $params = []) {
        $this->executeQuery($sql, $params);
        return $this->connection->lastInsertId();
    }

    /**
     * Actualizar/eliminar registros y obtener cantidad afectada
     */
    public function update($sql, $params = []) {
        $stmt = $this->executeQuery($sql, $params);
        return $stmt->rowCount();
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
     * Cancelar transacción
     */
    public function rollback() {
        return $this->connection->rollback();
    }

    /**
     * Obtener información de la base de datos
     */
    public function getDatabaseInfo() {
        try {
            $version = $this->fetch("SELECT VERSION() as version");
            $tables = $this->fetchAll("SHOW TABLES");
            
            return [
                'version' => $version['version'],
                'database' => $this->db_name,
                'tables_count' => count($tables),
                'connection_status' => 'connected'
            ];
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
    public function tableExists($tableName) {
        try {
            $result = $this->fetch(
                "SELECT COUNT(*) as count FROM information_schema.tables 
                 WHERE table_schema = ? AND table_name = ?",
                [$this->db_name, $tableName]
            );
            return $result['count'] > 0;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Limpiar sesiones expiradas
     */
    public function cleanExpiredSessions() {
        try {
            $deleted = $this->update(
                "DELETE FROM sessions WHERE expires_at < NOW()"
            );
            return $deleted;
        } catch (Exception $e) {
            error_log("Error limpiando sesiones: " . $e->getMessage());
            return 0;
        }
    }
}

/**
 * Función helper para obtener conexión de base de datos
 * Mantiene compatibilidad con código existente
 */
function getDBConnection() {
    try {
        return Database::getInstance()->getConnection();
    } catch (Exception $e) {
        error_log("Error obteniendo conexión: " . $e->getMessage());
        return null;
    }
}

/**
 * Función helper para obtener instancia de Database
 */
function getDatabase() {
    return Database::getInstance();
}

/**
 * Manejo de peticiones AJAX para verificación de estado
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && 
    isset($_SERVER['CONTENT_TYPE']) && 
    strpos($_SERVER['CONTENT_TYPE'], 'application/json') !== false) {
    
    header('Content-Type: application/json');
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (isset($input['action']) && $input['action'] === 'test_connection') {
        try {
            $db = Database::getInstance();
            $info = $db->getDatabaseInfo();
            
            // Verificar tablas principales
            $requiredTables = ['users', 'sessions', 'access_log', 'devices', 'relay_status'];
            $existingTables = [];
            
            foreach ($requiredTables as $table) {
                $existingTables[$table] = $db->tableExists($table);
            }
            
            echo json_encode([
                'success' => true,
                'database_info' => $info,
                'tables' => $existingTables,
                'message' => 'Conexión exitosa'
            ]);
            
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage(),
                'message' => 'Error de conexión a la base de datos'
            ]);
        }
        exit;
    }
}

// Limpiar sesiones expiradas automáticamente (ejecutar ocasionalmente)
if (rand(1, 100) === 1) {
    try {
        $db = Database::getInstance();
        $db->cleanExpiredSessions();
    } catch (Exception $e) {
        error_log("Error en limpieza automática de sesiones: " . $e->getMessage());
    }
}
?>
