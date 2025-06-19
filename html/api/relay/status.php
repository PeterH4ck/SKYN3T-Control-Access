// ===========================
// ARCHIVO: /var/www/html/api/relay/status.php (MEJORADO)
// DESCRIPCIÓN: Estado actual del relé con más información
// ===========================
?>
<?php
require_once '../../includes/config.php';
require_once '../../includes/database.php';
require_once '../../includes/auth.php';
require_once '../../includes/security.php';

// Headers
header('Content-Type: application/json; charset=UTF-8');
cors_headers();

// Solo permitir GET
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// Verificar autenticación
$auth_result = verify_api_auth();
if (!$auth_result['success']) {
    http_response_code(401);
    echo json_encode(['error' => $auth_result['message']]);
    exit;
}

try {
    $db = Database::getInstance()->getConnection();
    
    // Obtener estado actual
    $stmt = $db->prepare("
        SELECT 
            rs.*,
            u.full_name as changed_by_name
        FROM relay_status rs
        LEFT JOIN users u ON u.username = rs.changed_by
        ORDER BY rs.changed_at DESC 
        LIMIT 1
    ");
    $stmt->execute();
    $current = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$current) {
        // Si no hay registros, crear uno inicial
        $stmt = $db->prepare("
            INSERT INTO relay_status (status, changed_by, reason, changed_at) 
            VALUES ('off', 'system', 'Initial state', NOW())
        ");
        $stmt->execute();
        
        $response = [
            'success' => true,
            'status' => 'off',
            'last_change' => date('Y-m-d H:i:s'),
            'changed_by' => 'system',
            'changed_by_name' => 'System',
            'reason' => 'Initial state',
            'duration' => 'Just now'
        ];
    } else {
        // Calcular duración del estado actual
        $duration = calculate_duration($current['changed_at']);
        
        $response = [
            'success' => true,
            'status' => $current['status'],
            'last_change' => $current['changed_at'],
            'changed_by' => $current['changed_by'],
            'changed_by_name' => $current['changed_by_name'] ?? $current['changed_by'],
            'reason' => $current['reason'] ?? 'No reason provided',
            'duration' => $duration
        ];
    }
    
    // Obtener estadísticas adicionales si el usuario es admin
    if (in_array($auth_result['user']['role'], ['Admin', 'SuperUser'])) {
        // Total de cambios hoy
        $stmt = $db->prepare("
            SELECT COUNT(*) as changes_today
            FROM relay_status
            WHERE DATE(changed_at) = CURDATE()
        ");
        $stmt->execute();
        $stats = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Tiempo total encendido hoy
        $stmt = $db->prepare("
            SELECT 
                SUM(
                    CASE 
                        WHEN status = 'on' THEN
                            TIMESTAMPDIFF(SECOND, 
                                changed_at, 
                                IFNULL(
                                    (SELECT changed_at 
                                     FROM relay_status rs2 
                                     WHERE rs2.changed_at > rs1.changed_at 
                                     ORDER BY changed_at 
                                     LIMIT 1),
                                    NOW()
                                )
                            )
                        ELSE 0
                    END
                ) as total_on_seconds
            FROM relay_status rs1
            WHERE DATE(changed_at) = CURDATE()
        ");
        $stmt->execute();
        $time_stats = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $response['statistics'] = [
            'changes_today' => (int)$stats['changes_today'],
            'total_on_time_today' => format_duration($time_stats['total_on_seconds'] ?? 0),
            'total_on_seconds_today' => (int)($time_stats['total_on_seconds'] ?? 0)
        ];
    }
    
    // Información del GPIO (simulada por ahora)
    $response['gpio_status'] = [
        'pin' => 23,
        'simulated' => true,
        'reading' => $current['status'] === 'on' ? 'HIGH' : 'LOW'
    ];
    
    echo json_encode($response);
    
} catch (Exception $e) {
    error_log("Relay status error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'error' => 'Failed to get relay status',
        'message' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
    ]);
}

// Función para calcular duración
function calculate_duration($timestamp) {
    $diff = time() - strtotime($timestamp);
    
    if ($diff < 60) {
        return 'Just now';
    } elseif ($diff < 3600) {
        $mins = floor($diff / 60);
        return $mins . ' minute' . ($mins > 1 ? 's' : '') . ' ago';
    } elseif ($diff < 86400) {
        $hours = floor($diff / 3600);
        return $hours . ' hour' . ($hours > 1 ? 's' : '') . ' ago';
    } else {
        $days = floor($diff / 86400);
        return $days . ' day' . ($days > 1 ? 's' : '') . ' ago';
    }
}

// Función para formatear duración
function format_duration($seconds) {
    if ($seconds < 60) {
        return $seconds . ' seconds';
    } elseif ($seconds < 3600) {
        $mins = floor($seconds / 60);
        return $mins . ' minute' . ($mins > 1 ? 's' : '');
    } else {
        $hours = floor($seconds / 3600);
        $mins = floor(($seconds % 3600) / 60);
        return $hours . 'h ' . $mins . 'm';
    }
}
