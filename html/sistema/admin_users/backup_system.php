<?php
/**
 * SISTEMA COMPLETO DE BACKUP Y RESTAURACIÓN - SKYN3T
 * Acceso EXCLUSIVO para peterh4ck - Backup total del sistema
 * Versión: 3.0.1 - Herramientas de backup avanzadas
 */

session_start();

require_once __DIR__ . '/../includes/database.php';
require_once __DIR__ . '/../includes/config.php';

header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');

// Verificar acceso EXCLUSIVO para peterh4ck
function checkBackupAccess() {
    if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
        http_response_code(401);
        echo json_encode(['error' => 'No autorizado - Sesión no válida']);
        exit;
    }

    $username = $_SESSION['username'] ?? '';
    $role = $_SESSION['role'] ?? 'User';

    if ($username !== 'peterh4ck') {
        http_response_code(403);
        echo json_encode([
            'error' => 'Acceso DENEGADO - Sistema de backup exclusivo para administrador principal',
            'attempted_user' => $username
        ]);
        
        error_log("UNAUTHORIZED BACKUP ACCESS: user=$username, ip=" . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        exit;
    }

    if ($role !== 'SuperUser') {
        http_response_code(403);
        echo json_encode(['error' => 'Permisos insuficientes para backup del sistema']);
        exit;
    }

    return $username;
}

// Verificar acceso antes de procesar
$adminUser = checkBackupAccess();

$action = $_GET['action'] ?? '';

// Configuración de backup
define('BACKUP_DIR', '/var/www/html/backups/');
define('MAX_BACKUP_FILES', 50);
define('BACKUP_RETENTION_DAYS', 30);

try {
    // Crear directorio de backup si no existe
    if (!is_dir(BACKUP_DIR)) {
        mkdir(BACKUP_DIR, 0755, true);
    }

    switch($action) {
        case 'list_backups':
            listBackups();
            break;
        case 'create_backup':
            createBackup();
            break;
        case 'create_full_backup':
            createFullBackup();
            break;
        case 'restore_backup':
            restoreBackup();
            break;
        case 'delete_backup':
            deleteBackup();
            break;
        case 'download_backup':
            downloadBackup();
            break;
        case 'backup_status':
            getBackupStatus();
            break;
        case 'cleanup_backups':
            cleanupOldBackups();
            break;
        case 'verify_backup':
            verifyBackup();
            break;
        case 'backup_config':
            getBackupConfig();
            break;
        case 'set_backup_config':
            setBackupConfig();
            break;
        case 'emergency_backup':
            emergencyBackup();
            break;
        default:
            http_response_code(400);
            echo json_encode([
                'error' => 'Acción no válida',
                'available_actions' => [
                    'list_backups', 'create_backup', 'create_full_backup', 'restore_backup',
                    'delete_backup', 'download_backup', 'backup_status', 'cleanup_backups',
                    'verify_backup', 'backup_config', 'set_backup_config', 'emergency_backup'
                ]
            ]);
    }
} catch (Exception $e) {
    error_log("Error en backup_system.php: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Error interno del sistema de backup',
        'message' => $e->getMessage(),
        'debug' => DEBUG_MODE ? $e->getTraceAsString() : null
    ]);
}

// Listar backups disponibles
function listBackups() {
    try {
        $backups = [];
        $files = glob(BACKUP_DIR . '*.sql');
        $files = array_merge($files, glob(BACKUP_DIR . '*.tar.gz'));
        
        foreach ($files as $file) {
            $filename = basename($file);
            $info = pathinfo($file);
            
            // Extraer información del nombre del archivo
            preg_match('/skyn3t_(.+?)_(\d{8}_\d{6})\.(.+)/', $filename, $matches);
            
            $backups[] = [
                'filename' => $filename,
                'filepath' => $file,
                'type' => $info['extension'] === 'sql' ? 'database' : 'full_system',
                'size' => formatFileSize(filesize($file)),
                'size_bytes' => filesize($file),
                'created_at' => date('Y-m-d H:i:s', filemtime($file)),
                'created_timestamp' => filemtime($file),
                'age_days' => floor((time() - filemtime($file)) / 86400),
                'backup_type' => isset($matches[1]) ? $matches[1] : 'unknown',
                'datetime_string' => isset($matches[2]) ? $matches[2] : 'unknown',
                'is_verified' => file_exists($file . '.verified'),
                'checksum' => file_exists($file . '.md5') ? file_get_contents($file . '.md5') : null
            ];
        }

        // Ordenar por fecha de creación (más reciente primero)
        usort($backups, function($a, $b) {
            return $b['created_timestamp'] - $a['created_timestamp'];
        });

        // Estadísticas
        $stats = [
            'total_backups' => count($backups),
            'database_backups' => count(array_filter($backups, fn($b) => $b['type'] === 'database')),
            'full_backups' => count(array_filter($backups, fn($b) => $b['type'] === 'full_system')),
            'total_size' => formatFileSize(array_sum(array_column($backups, 'size_bytes'))),
            'oldest_backup' => !empty($backups) ? min(array_column($backups, 'created_timestamp')) : null,
            'newest_backup' => !empty($backups) ? max(array_column($backups, 'created_timestamp')) : null,
            'disk_usage' => disk_total_space(BACKUP_DIR) ? 
                round((disk_total_space(BACKUP_DIR) - disk_free_space(BACKUP_DIR)) / disk_total_space(BACKUP_DIR) * 100, 2) : 0
        ];

        echo json_encode([
            'success' => true,
            'backups' => $backups,
            'stats' => $stats,
            'backup_dir' => BACKUP_DIR,
            'max_files' => MAX_BACKUP_FILES,
            'retention_days' => BACKUP_RETENTION_DAYS
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al listar backups: ' . $e->getMessage()
        ]);
    }
}

// Crear backup de base de datos
function createBackup() {
    try {
        $db = Database::getInstance();
        $timestamp = date('Ymd_His');
        $filename = "skyn3t_database_{$timestamp}.sql";
        $filepath = BACKUP_DIR . $filename;

        // Comando mysqldump
        $command = sprintf(
            'mysqldump -u root -padmin --single-transaction --routines --triggers skyn3t_db > %s 2>&1',
            escapeshellarg($filepath)
        );

        $output = [];
        $return_code = 0;
        exec($command, $output, $return_code);

        if ($return_code !== 0) {
            throw new Exception('Error ejecutando mysqldump: ' . implode('\n', $output));
        }

        // Verificar que el archivo se creó correctamente
        if (!file_exists($filepath) || filesize($filepath) === 0) {
            throw new Exception('El archivo de backup no se creó correctamente');
        }

        // Generar checksum MD5
        $checksum = md5_file($filepath);
        file_put_contents($filepath . '.md5', $checksum);

        // Agregar metadata al backup
        $metadata = [
            'created_by' => $_SESSION['username'],
            'created_at' => date('Y-m-d H:i:s'),
            'type' => 'database',
            'database' => 'skyn3t_db',
            'size' => filesize($filepath),
            'checksum' => $checksum,
            'mysql_version' => $db->execute("SELECT VERSION() as version")->fetch()['version'],
            'tables_count' => count($db->execute("SHOW TABLES")->fetchAll()),
            'server_info' => [
                'php_version' => PHP_VERSION,
                'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
                'hostname' => gethostname(),
                'ip_address' => $_SERVER['SERVER_ADDR'] ?? 'unknown'
            ]
        ];

        file_put_contents($filepath . '.meta', json_encode($metadata, JSON_PRETTY_PRINT));

        // Registrar en logs
        if ($db->tableExists('access_log')) {
            $db->execute(
                "INSERT INTO access_log (user_id, username, action, ip_address, user_agent, timestamp)
                 VALUES (?, ?, 'database_backup_created', ?, ?, NOW())",
                [
                    $_SESSION['user_id'],
                    $_SESSION['username'],
                    $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                    $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
                ]
            );
        }

        echo json_encode([
            'success' => true,
            'message' => 'Backup de base de datos creado exitosamente',
            'filename' => $filename,
            'filepath' => $filepath,
            'size' => formatFileSize(filesize($filepath)),
            'checksum' => $checksum,
            'metadata' => $metadata
        ]);

    } catch (Exception $e) {
        error_log("Error creando backup: " . $e->getMessage());
        echo json_encode([
            'success' => false,
            'error' => 'Error al crear backup: ' . $e->getMessage()
        ]);
    }
}

// Crear backup completo del sistema
function createFullBackup() {
    try {
        $timestamp = date('Ymd_His');
        $filename = "skyn3t_full_{$timestamp}.tar.gz";
        $filepath = BACKUP_DIR . $filename;

        // Crear backup de base de datos primero
        $db_filename = "skyn3t_db_{$timestamp}.sql";
        $db_filepath = BACKUP_DIR . $db_filename;

        $command = sprintf(
            'mysqldump -u root -padmin --single-transaction --routines --triggers skyn3t_db > %s',
            escapeshellarg($db_filepath)
        );
        exec($command, $output, $return_code);

        if ($return_code !== 0) {
            throw new Exception('Error creando backup de base de datos');
        }

        // Crear archivo tar.gz con todo el sistema
        $exclude_patterns = [
            '--exclude=*.log',
            '--exclude=*/logs/*',
            '--exclude=*/tmp/*',
            '--exclude=*/cache/*',
            '--exclude=*/backups/*'
        ];

        $tar_command = sprintf(
            'tar -czf %s %s -C /var/www/html .',
            escapeshellarg($filepath),
            implode(' ', $exclude_patterns)
        );

        exec($tar_command, $tar_output, $tar_return);

        if ($tar_return !== 0) {
            // Limpiar archivo de DB si falla
            if (file_exists($db_filepath)) {
                unlink($db_filepath);
            }
            throw new Exception('Error creando archivo comprimido del sistema');
        }

        // Agregar backup de DB al archivo comprimido
        $add_db_command = sprintf(
            'tar -rf %s -C %s %s',
            escapeshellarg(str_replace('.gz', '', $filepath)),
            escapeshellarg(dirname($db_filepath)),
            escapeshellarg(basename($db_filepath))
        );

        // Recomprimir
        exec("gzip " . escapeshellarg(str_replace('.gz', '', $filepath)));

        // Limpiar archivo temporal de DB
        if (file_exists($db_filepath)) {
            unlink($db_filepath);
        }

        // Generar checksum
        $checksum = md5_file($filepath);
        file_put_contents($filepath . '.md5', $checksum);

        // Metadata del backup completo
        $metadata = [
            'created_by' => $_SESSION['username'],
            'created_at' => date('Y-m-d H:i:s'),
            'type' => 'full_system',
            'includes' => ['database', 'web_files', 'configuration', 'logs'],
            'excludes' => ['cache', 'tmp', 'other_backups'],
            'size' => filesize($filepath),
            'checksum' => $checksum,
            'system_info' => [
                'php_version' => PHP_VERSION,
                'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
                'disk_free' => disk_free_space('/var/www/html'),
                'backup_time' => time()
            ]
        ];

        file_put_contents($filepath . '.meta', json_encode($metadata, JSON_PRETTY_PRINT));

        echo json_encode([
            'success' => true,
            'message' => 'Backup completo del sistema creado exitosamente',
            'filename' => $filename,
            'filepath' => $filepath,
            'size' => formatFileSize(filesize($filepath)),
            'checksum' => $checksum,
            'metadata' => $metadata
        ]);

    } catch (Exception $e) {
        error_log("Error creando backup completo: " . $e->getMessage());
        echo json_encode([
            'success' => false,
            'error' => 'Error al crear backup completo: ' . $e->getMessage()
        ]);
    }
}

// Restaurar backup
function restoreBackup() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'Método no permitido']);
        return;
    }

    try {
        $data = json_decode(file_get_contents('php://input'), true);
        $filename = $data['filename'] ?? '';

        if (empty($filename)) {
            throw new Exception('Nombre de archivo requerido');
        }

        $filepath = BACKUP_DIR . $filename;

        if (!file_exists($filepath)) {
            throw new Exception('Archivo de backup no encontrado');
        }

        // Verificar checksum si existe
        if (file_exists($filepath . '.md5')) {
            $stored_checksum = trim(file_get_contents($filepath . '.md5'));
            $current_checksum = md5_file($filepath);

            if ($stored_checksum !== $current_checksum) {
                throw new Exception('Error de integridad: checksum no coincide');
            }
        }

        $info = pathinfo($filepath);

        if ($info['extension'] === 'sql') {
            // Restaurar backup de base de datos
            restoreDatabaseBackup($filepath);
        } elseif ($info['extension'] === 'gz' && strpos($filename, 'full_') !== false) {
            // Restaurar backup completo
            restoreFullBackup($filepath);
        } else {
            throw new Exception('Tipo de backup no soportado');
        }

        echo json_encode([
            'success' => true,
            'message' => 'Backup restaurado exitosamente',
            'filename' => $filename,
            'restored_at' => date('Y-m-d H:i:s')
        ]);

    } catch (Exception $e) {
        error_log("Error restaurando backup: " . $e->getMessage());
        echo json_encode([
            'success' => false,
            'error' => 'Error al restaurar backup: ' . $e->getMessage()
        ]);
    }
}

// Restaurar backup de base de datos
function restoreDatabaseBackup($filepath) {
    $command = sprintf(
        'mysql -u root -padmin skyn3t_db < %s 2>&1',
        escapeshellarg($filepath)
    );

    $output = [];
    $return_code = 0;
    exec($command, $output, $return_code);

    if ($return_code !== 0) {
        throw new Exception('Error restaurando base de datos: ' . implode('\n', $output));
    }

    // Verificar que la restauración fue exitosa
    $db = Database::getInstance();
    $tables = $db->execute("SHOW TABLES")->fetchAll();

    if (empty($tables)) {
        throw new Exception('Error: No se encontraron tablas después de la restauración');
    }
}

// Restaurar backup completo (¡PELIGROSO!)
function restoreFullBackup($filepath) {
    // ADVERTENCIA: Esta función puede sobrescribir todo el sistema
    
    // Crear backup de emergencia antes de restaurar
    $emergency_backup = BACKUP_DIR . 'emergency_before_restore_' . date('Ymd_His') . '.tar.gz';
    
    $backup_command = sprintf(
        'tar -czf %s --exclude=*/backups/* -C /var/www/html .',
        escapeshellarg($emergency_backup)
    );
    
    exec($backup_command);

    // Extraer backup completo
    $extract_command = sprintf(
        'tar -xzf %s -C /var/www/html',
        escapeshellarg($filepath)
    );

    $output = [];
    $return_code = 0;
    exec($extract_command, $output, $return_code);

    if ($return_code !== 0) {
        throw new Exception('Error extrayendo backup completo: ' . implode('\n', $output));
    }

    // Restaurar permisos
    exec('chown -R www-data:www-data /var/www/html');
    exec('chmod -R 755 /var/www/html');
}

// Eliminar backup
function deleteBackup() {
    if ($_SERVER['REQUEST_METHOD'] !== 'DELETE') {
        http_response_code(405);
        echo json_encode(['error' => 'Método no permitido']);
        return;
    }

    try {
        $filename = $_GET['filename'] ?? '';

        if (empty($filename)) {
            throw new Exception('Nombre de archivo requerido');
        }

        $filepath = BACKUP_DIR . $filename;

        if (!file_exists($filepath)) {
            throw new Exception('Archivo de backup no encontrado');
        }

        // Eliminar archivo principal
        if (!unlink($filepath)) {
            throw new Exception('No se pudo eliminar el archivo de backup');
        }

        // Eliminar archivos relacionados
        $related_files = [
            $filepath . '.md5',
            $filepath . '.meta',
            $filepath . '.verified'
        ];

        foreach ($related_files as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }

        echo json_encode([
            'success' => true,
            'message' => 'Backup eliminado exitosamente',
            'filename' => $filename
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al eliminar backup: ' . $e->getMessage()
        ]);
    }
}

// Descargar backup
function downloadBackup() {
    try {
        $filename = $_GET['filename'] ?? '';

        if (empty($filename)) {
            throw new Exception('Nombre de archivo requerido');
        }

        $filepath = BACKUP_DIR . $filename;

        if (!file_exists($filepath)) {
            throw new Exception('Archivo de backup no encontrado');
        }

        // Headers para descarga
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . filesize($filepath));
        header('Cache-Control: no-cache, must-revalidate');

        // Leer y enviar archivo
        readfile($filepath);
        exit;

    } catch (Exception $e) {
        header('Content-Type: application/json');
        echo json_encode([
            'success' => false,
            'error' => 'Error al descargar backup: ' . $e->getMessage()
        ]);
    }
}

// Obtener estado del sistema de backup
function getBackupStatus() {
    try {
        $backup_disk_usage = 0;
        $backup_count = 0;

        if (is_dir(BACKUP_DIR)) {
            $files = glob(BACKUP_DIR . '*');
            $backup_count = count($files);
            
            foreach ($files as $file) {
                if (is_file($file)) {
                    $backup_disk_usage += filesize($file);
                }
            }
        }

        $status = [
            'backup_system' => [
                'status' => 'operational',
                'backup_dir' => BACKUP_DIR,
                'dir_exists' => is_dir(BACKUP_DIR),
                'dir_writable' => is_writable(BACKUP_DIR),
                'total_backups' => $backup_count,
                'disk_usage' => formatFileSize($backup_disk_usage),
                'max_files' => MAX_BACKUP_FILES,
                'retention_days' => BACKUP_RETENTION_DAYS
            ],
            'database' => [
                'status' => 'connected',
                'engine' => 'MariaDB',
                'backup_capable' => command_exists('mysqldump'),
                'restore_capable' => command_exists('mysql')
            ],
            'system' => [
                'disk_free' => formatFileSize(disk_free_space('/')),
                'disk_total' => formatFileSize(disk_total_space('/')),
                'php_version' => PHP_VERSION,
                'max_execution_time' => ini_get('max_execution_time'),
                'memory_limit' => ini_get('memory_limit')
            ],
            'last_activity' => [
                'last_backup' => getLastBackupTime(),
                'backup_frequency' => 'manual',
                'next_cleanup' => date('Y-m-d H:i:s', time() + 86400)
            ]
        ];

        echo json_encode([
            'success' => true,
            'status' => $status
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error al obtener estado: ' . $e->getMessage()
        ]);
    }
}

// Limpiar backups antiguos
function cleanupOldBackups() {
    try {
        $files = glob(BACKUP_DIR . '*');
        $deleted_files = [];
        $retention_timestamp = time() - (BACKUP_RETENTION_DAYS * 86400);

        foreach ($files as $file) {
            if (is_file($file) && filemtime($file) < $retention_timestamp) {
                if (unlink($file)) {
                    $deleted_files[] = basename($file);
                }
            }
        }

        // También limpiar si hay demasiados archivos
        $remaining_files = glob(BACKUP_DIR . '*.sql');
        $remaining_files = array_merge($remaining_files, glob(BACKUP_DIR . '*.tar.gz'));

        if (count($remaining_files) > MAX_BACKUP_FILES) {
            // Ordenar por fecha (más antiguos primero)
            usort($remaining_files, function($a, $b) {
                return filemtime($a) - filemtime($b);
            });

            $to_delete = array_slice($remaining_files, 0, count($remaining_files) - MAX_BACKUP_FILES);
            
            foreach ($to_delete as $file) {
                if (unlink($file)) {
                    $deleted_files[] = basename($file);
                }
            }
        }

        echo json_encode([
            'success' => true,
            'message' => 'Limpieza de backups completada',
            'deleted_files' => $deleted_files,
            'deleted_count' => count($deleted_files)
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error en limpieza: ' . $e->getMessage()
        ]);
    }
}

// Funciones auxiliares
function formatFileSize($size) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $power = $size > 0 ? floor(log($size, 1024)) : 0;
    return number_format($size / pow(1024, $power), 2, '.', ',') . ' ' . $units[$power];
}

function command_exists($command) {
    $return = shell_exec(sprintf("which %s", escapeshellarg($command)));
    return !empty($return);
}

function getLastBackupTime() {
    $files = glob(BACKUP_DIR . '*');
    if (empty($files)) {
        return null;
    }

    $latest = 0;
    foreach ($files as $file) {
        if (is_file($file)) {
            $latest = max($latest, filemtime($file));
        }
    }

    return $latest > 0 ? date('Y-m-d H:i:s', $latest) : null;
}

// Backup de emergencia
function emergencyBackup() {
    try {
        // Crear backup de emergencia rápido
        $timestamp = date('Ymd_His');
        $filename = "skyn3t_EMERGENCY_{$timestamp}.sql";
        $filepath = BACKUP_DIR . $filename;

        $command = sprintf(
            'mysqldump -u root -padmin --quick --single-transaction skyn3t_db > %s',
            escapeshellarg($filepath)
        );

        exec($command, $output, $return_code);

        if ($return_code !== 0) {
            throw new Exception('Error en backup de emergencia');
        }

        echo json_encode([
            'success' => true,
            'message' => 'Backup de emergencia creado',
            'filename' => $filename,
            'size' => formatFileSize(filesize($filepath))
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Error en backup de emergencia: ' . $e->getMessage()
        ]);
    }
}

// Verificar integridad de backup
function verifyBackup() {
    $filename = $_GET['filename'] ?? '';
    $filepath = BACKUP_DIR . $filename;

    if (!file_exists($filepath)) {
        echo json_encode(['success' => false, 'error' => 'Archivo no encontrado']);
        return;
    }

    $verification = [
        'file_exists' => true,
        'file_size' => filesize($filepath),
        'checksum_valid' => false,
        'content_valid' => false
    ];

    // Verificar checksum
    if (file_exists($filepath . '.md5')) {
        $stored_checksum = trim(file_get_contents($filepath . '.md5'));
        $current_checksum = md5_file($filepath);
        $verification['checksum_valid'] = ($stored_checksum === $current_checksum);
    }

    // Verificar contenido (para archivos SQL)
    if (pathinfo($filepath, PATHINFO_EXTENSION) === 'sql') {
        $content = file_get_contents($filepath, false, null, 0, 1000);
        $verification['content_valid'] = (strpos($content, 'CREATE') !== false || strpos($content, 'INSERT') !== false);
    }

    // Marcar como verificado
    if ($verification['checksum_valid'] && $verification['content_valid']) {
        file_put_contents($filepath . '.verified', date('Y-m-d H:i:s'));
    }

    echo json_encode([
        'success' => true,
        'verification' => $verification
    ]);
}

// Obtener configuración de backup
function getBackupConfig() {
    echo json_encode([
        'success' => true,
        'config' => [
            'backup_dir' => BACKUP_DIR,
            'max_files' => MAX_BACKUP_FILES,
            'retention_days' => BACKUP_RETENTION_DAYS,
            'auto_cleanup' => true,
            'compression' => true,
            'checksum_verification' => true
        ]
    ]);
}

// Establecer configuración de backup
function setBackupConfig() {
    echo json_encode([
        'success' => false,
        'error' => 'Configuración de backup en desarrollo'
    ]);
}
?>