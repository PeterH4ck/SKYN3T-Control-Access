<?php
/**
 * Archivo: /var/www/html/api/notifications/list.php
 * API endpoint para listar notificaciones del usuario
 */

// Definir constante del sistema
define('SKYN3T_SYSTEM', true);

// Headers de seguridad y CORS
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Manejo de solicitudes OPTIONS (CORS preflight)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Solo permitir GET
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'message' => 'Método no permitido',
        'error_code' => 'METHOD_NOT_ALLOWED'
    ]);
    exit;
}

// Incluir sistema de autenticación
require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/database.php';
require_once __DIR__ . '/../../includes/security.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/session.php';

try {
    // Verificar autenticación
    $auth = Auth::getInstance();
    $user = $auth->requireAuth();
    
    if (!$user) {
        exit; // requireAuth ya maneja la respuesta
    }
    
    $db = Database::getInstance();
    
    // Crear tabla de notificaciones si no existe
    createNotificationsTable($db);
    
    // Parámetros de filtrado y paginación
    $page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
    $limit = isset($_GET['limit']) ? max(1, min(50, (int)$_GET['limit'])) : 20;
    $offset = ($page - 1) * $limit;
    
    $type = isset($_GET['type']) ? sanitize($_GET['type']) : null;
    $read = isset($_GET['read']) ? (bool)$_GET['read'] : null;
    $priority = isset($_GET['priority']) ? sanitize($_GET['priority']) : null;
    
    // Construir consulta WHERE
    $whereConditions = ['user_id = ?'];
    $params = [$user['id']];
    
    if ($type && in_array($type, ['system', 'security', 'relay', 'device', 'user'])) {
        $whereConditions[] = "type = ?";
        $params[] = $type;
    }
    
    if ($read !== null) {
        $whereConditions[] = "is_read = ?";
        $params[] = $read ? 1 : 0;
    }
    
    if ($priority && in_array($priority, ['low', 'medium', 'high', 'critical'])) {
        $whereConditions[] = "priority = ?";
        $params[] = $priority;
    }
    
    $whereClause = 'WHERE ' . implode(' AND ', $whereConditions);
    
    // Consulta principal
    $sql = "
        SELECT *
        FROM notifications 
        $whereClause
        ORDER BY created_at DESC
        LIMIT $limit OFFSET $offset
    ";
    
    $notifications = $db->fetchAll($sql, $params);
    
    // Contar total de notificaciones
    $countSql = "SELECT COUNT(*) as total FROM notifications $whereClause";
    $totalResult = $db->fetch($countSql, $params);
    $total = $totalResult['total'];
    
    // Obtener estadísticas de notificaciones
    $stats = $db->fetch("
        SELECT 
            COUNT(*) as total_notifications,
            SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END) as unread_count,
            SUM(CASE WHEN is_read = 1 THEN 1 ELSE 0 END) as read_count,
            SUM(CASE WHEN priority = 'critical' THEN 1 ELSE 0 END) as critical_count
        FROM notifications 
        WHERE user_id = ?
    ", [$user['id']]);
    
    // Obtener notificaciones por tipo
    $typeStats = $db->fetchAll("
        SELECT type, COUNT(*) as count 
        FROM notifications 
        WHERE user_id = ? 
        GROUP BY type 
        ORDER BY count DESC
    ", [$user['id']]);
    
    // Formatear notificaciones
    $formattedNotifications = array_map(function($notification) {
        return [
            'id' => (int)$notification['id'],
            'type' => $notification['type'],
            'title' => $notification['title'],
            'message' => $notification['message'],
            'priority' => $notification['priority'],
            'is_read' => (bool)$notification['is_read'],
            'created_at' => $notification['created_at'],
            'read_at' => $notification['read_at'],
            'expires_at' => $notification['expires_at'],
            'metadata' => $notification['metadata'] ? json_decode($notification['metadata'], true) : null,
            'time_ago' => timeAgo($notification['created_at'])
        ];
    }, $notifications);
    
    // Calcular información de paginación
    $totalPages = ceil($total / $limit);
    $hasNext = $page < $totalPages;
    $hasPrev = $page > 1;
    
    // Generar notificaciones automáticas del sistema si es necesario
    generateSystemNotifications($db, $user);
    
    // Respuesta exitosa
    echo json_encode([
        'success' => true,
        'notifications' => $formattedNotifications,
        'pagination' => [
            'current_page' => $page,
            'total_pages' => $totalPages,
            'total_items' => (int)$total,
            'items_per_page' => $limit,
            'has_next' => $hasNext,
            'has_previous' => $hasPrev
        ],
        'statistics' => [
            'total_notifications' => (int)$stats['total_notifications'],
            'unread_count' => (int)$stats['unread_count'],
            'read_count' => (int)$stats['read_count'],
            'critical_count' => (int)$stats['critical_count']
        ],
        'type_distribution' => array_map(function($type) {
            return [
                'type' => $type['type'],
                'count' => (int)$type['count']
            ];
        }, $typeStats),
        'filters_applied' => [
            'type' => $type,
            'read' => $read,
            'priority' => $priority
        ],
        'timestamp' => date('Y-m-d H:i:s')
    ]);
    
} catch (Exception $e) {
    error_log("Error obteniendo notificaciones: " . $e->getMessage());
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Error interno del servidor',
        'error_code' => 'INTERNAL_ERROR'
    ]);
}

/**
 * Crear tabla de notificaciones si no existe
 */
function createNotificationsTable($db) {
    try {
        $db->executeQuery("
            CREATE TABLE IF NOT EXISTS notifications (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                type ENUM('system','security','relay','device','user') NOT NULL DEFAULT 'system',
                title VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                priority ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
                is_read TINYINT(1) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read_at TIMESTAMP NULL,
                expires_at TIMESTAMP NULL,
                metadata JSON,
                
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_created_at (created_at),
                INDEX idx_is_read (is_read),
                INDEX idx_type (type),
                INDEX idx_priority (priority)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ");
    } catch (Exception $e) {
        error_log("Error creando tabla notifications: " . $e->getMessage());
    }
}

/**
 * Generar notificaciones automáticas del sistema
 */
function generateSystemNotifications($db, $user) {
    try {
        // Solo generar para admins y super users
        if (!in_array($user['role'], ['Admin', 'SuperUser'])) {
            return;
        }
        
        // Verificar si ya se generaron notificaciones hoy
        $todayNotifications = $db->fetch("
            SELECT COUNT(*) as count 
            FROM notifications 
            WHERE user_id = ? AND type = 'system' 
            AND DATE(created_at) = CURDATE()
        ", [$user['id']]);
        
        if ($todayNotifications['count'] > 0) {
            return; // Ya se generaron notificaciones hoy
        }
        
        // Notificación de dispositivos inactivos
        $inactiveDevices = $db->fetch("
            SELECT COUNT(*) as count 
            FROM devices 
            WHERE status = 'inactive'
        ");
        
        if ($inactiveDevices['count'] > 0) {
            $db->executeQuery("
                INSERT INTO notifications (user_id, type, title, message, priority, metadata)
                VALUES (?, 'device', 'Dispositivos Inactivos', ?, 'medium', ?)
            ", [
                $user['id'],
                "Tienes {$inactiveDevices['count']} dispositivo(s) inactivo(s) que requieren atención.",
                json_encode(['device_count' => $inactiveDevices['count']])
            ]);
        }
        
        // Notificación de usuarios bloqueados
        $lockedUsers = $db->fetch("
            SELECT COUNT(*) as count 
            FROM users 
            WHERE locked_until > NOW()
        ");
        
        if ($lockedUsers['count'] > 0) {
            $db->executeQuery("
                INSERT INTO notifications (user_id, type, title, message, priority, metadata)
                VALUES (?, 'security', 'Usuarios Bloqueados', ?, 'high', ?)
            ", [
                $user['id'],
                "Hay {$lockedUsers['count']} usuario(s) temporalmente bloqueado(s) por intentos fallidos.",
                json_encode(['locked_count' => $lockedUsers['count']])
            ]);
        }
        
        // Notificación de actividad del relé
        $relayChanges = $db->fetch("
            SELECT COUNT(*) as count 
            FROM relay_status 
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        
        if ($relayChanges['count'] > 10) {
            $db->executeQuery("
                INSERT INTO notifications (user_id, type, title, message, priority, metadata)
                VALUES (?, 'relay', 'Alta Actividad del Relé', ?, 'medium', ?)
            ", [
                $user['id'],
                "El relé ha tenido {$relayChanges['count']} cambios en las últimas 24 horas.",
                json_encode(['changes_24h' => $relayChanges['count']])
            ]);
        }
        
        // Notificación de bienvenida para nuevos usuarios
        $accountAge = floor((time() - strtotime($user['last_login'] ?? $user['created_at'])) / 86400);
        if ($accountAge <= 1) {
            $db->executeQuery("
                INSERT INTO notifications (user_id, type, title, message, priority, metadata)
                VALUES (?, 'system', 'Bienvenido a SKYN3T', ?, 'low', ?)
            ", [
                $user['id'],
                "¡Bienvenido al sistema SKYN3T! Explora las diferentes funciones disponibles según tu rol.",
                json_encode(['welcome' => true, 'account_age_days' => $accountAge])
            ]);
        }
        
    } catch (Exception $e) {
        error_log("Error generando notificaciones automáticas: " . $e->getMessage());
    }
}

/**
 * Calcular tiempo transcurrido desde una fecha
 */
function timeAgo($datetime) {
    $time = time() - strtotime($datetime);
    
    if ($time < 60) {
        return 'hace ' . $time . ' segundo' . ($time != 1 ? 's' : '');
    } elseif ($time < 3600) {
        $minutes = floor($time / 60);
        return 'hace ' . $minutes . ' minuto' . ($minutes != 1 ? 's' : '');
    } elseif ($time < 86400) {
        $hours = floor($time / 3600);
        return 'hace ' . $hours . ' hora' . ($hours != 1 ? 's' : '');
    } elseif ($time < 2592000) {
        $days = floor($time / 86400);
        return 'hace ' . $days . ' día' . ($days != 1 ? 's' : '');
    } else {
        $months = floor($time / 2592000);
        return 'hace ' . $months . ' mes' . ($months != 1 ? 'es' : '');
    }
}
?>
