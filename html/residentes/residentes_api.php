<?php
/**
 * API para Gestión de Residentes
 * Solo accesible para SuperUser, SupportUser y Admin
 */

session_start();
require_once __DIR__ . '/../includes/database_mysql.php';

header('Content-Type: application/json');

// Verificar autenticación y permisos
function checkAccess() {
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['role'])) {
        http_response_code(401);
        echo json_encode(['error' => 'No autorizado']);
        exit;
    }
    
    $allowed_roles = ['superUser', 'SupportUser', 'Admin'];
    if (!in_array($_SESSION['role'], $allowed_roles)) {
        http_response_code(403);
        echo json_encode(['error' => 'Acceso denegado - Permisos insuficientes']);
        exit;
    }
}

// Verificar acceso antes de procesar
checkAccess();

$action = $_GET['action'] ?? '';
$db = Database::getInstance();

try {
    switch($action) {
        case 'stats':
            getStatistics();
            break;
        case 'list':
            getResidents();
            break;
        case 'get':
            getResident();
            break;
        case 'create':
            createResident();
            break;
        case 'update':
            updateResident();
            break;
        case 'delete':
            deleteResident();
            break;
        case 'pending':
            getPendingRequests();
            break;
        case 'approve':
            approveRequest();
            break;
        case 'reject':
            rejectRequest();
            break;
        case 'filter':
            filterResidents();
            break;
        default:
            http_response_code(400);
            echo json_encode(['error' => 'Acción no válida']);
    }
} catch (Exception $e) {
    error_log("Error en residentes_api.php: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Error interno del servidor']);
}

// Obtener estadísticas
function getStatistics() {
    global $db;
    
    $stats = $db->queryOne("SELECT * FROM vista_estadisticas_residentes");
    
    echo json_encode([
        'success' => true,
        'stats' => [
            'total_residentes' => (int)$stats['total_residentes'],
            'unidades_ocupadas' => (int)$stats['unidades_ocupadas'],
            'accesos_activos' => (int)$stats['accesos_completos'],
            'solicitudes_pendientes' => (int)$stats['solicitudes_pendientes'],
            'residentes_activos' => (int)$stats['residentes_activos'],
            'residentes_inactivos' => (int)$stats['residentes_inactivos'],
            'propietarios' => (int)$stats['propietarios'],
            'arrendatarios' => (int)$stats['arrendatarios']
        ]
    ]);
}

// Listar residentes
function getResidents() {
    global $db;
    
    $filter = $_GET['filter'] ?? '';
    $search = $_GET['search'] ?? '';
    $limit = min((int)($_GET['limit'] ?? 50), 100);
    $offset = (int)($_GET['offset'] ?? 0);
    
    $where = "WHERE 1=1";
    $params = [];
    
    // Filtros
    if ($filter) {
        switch($filter) {
            case 'active':
                $where .= " AND estado = 'activo'";
                break;
            case 'inactive':
                $where .= " AND estado = 'inactivo'";
                break;
            case 'pending':
                $where .= " AND estado = 'pendiente'";
                break;
            case 'tower-a':
                $where .= " AND torre = 'A'";
                break;
            case 'tower-b':
                $where .= " AND torre = 'B'";
                break;
            case 'tower-c':
                $where .= " AND torre = 'C'";
                break;
        }
    }
    
    // Búsqueda
    if ($search) {
        $where .= " AND (nombre LIKE :search OR apellido LIKE :search OR email LIKE :search OR CONCAT(torre, '-', apartamento) LIKE :search OR cedula LIKE :search)";
        $params['search'] = "%$search%";
    }
    
    $sql = "SELECT r.*, 
                   CONCAT(r.nombre, ' ', r.apellido) as nombre_completo,
                   CONCAT(r.torre, '-', r.apartamento) as unidad,
                   u1.username as creado_por_usuario,
                   u2.username as modificado_por_usuario
            FROM residentes r
            LEFT JOIN usuarios u1 ON r.creado_por = u1.id
            LEFT JOIN usuarios u2 ON r.modificado_por = u2.id
            $where
            ORDER BY r.fecha_registro DESC
            LIMIT $limit OFFSET $offset";
    
    $residents = $db->query($sql, $params);
    
    // Contar total para paginación
    $countSql = "SELECT COUNT(*) as total FROM residentes r $where";
    $total = $db->queryOne($countSql, $params)['total'];
    
    echo json_encode([
        'success' => true,
        'residents' => $residents,
        'total' => (int)$total,
        'limit' => $limit,
        'offset' => $offset
    ]);
}

// Obtener residente específico
function getResident() {
    global $db;
    
    $id = (int)($_GET['id'] ?? 0);
    if (!$id) {
        http_response_code(400);
        echo json_encode(['error' => 'ID de residente requerido']);
        return;
    }
    
    $resident = $db->queryOne(
        "SELECT r.*, 
                CONCAT(r.nombre, ' ', r.apellido) as nombre_completo,
                CONCAT(r.torre, '-', r.apartamento) as unidad,
                u1.username as creado_por_usuario,
                u2.username as modificado_por_usuario
         FROM residentes r
         LEFT JOIN usuarios u1 ON r.creado_por = u1.id
         LEFT JOIN usuarios u2 ON r.modificado_por = u2.id
         WHERE r.id = :id",
        ['id' => $id]
    );
    
    if (!$resident) {
        http_response_code(404);
        echo json_encode(['error' => 'Residente no encontrado']);
        return;
    }
    
    // Obtener contactos de emergencia
    $contacts = $db->query(
        "SELECT * FROM contactos_emergencia WHERE residente_id = :id ORDER BY es_principal DESC",
        ['id' => $id]
    );
    
    // Obtener vehículos
    $vehicles = $db->query(
        "SELECT * FROM vehiculos_residentes WHERE residente_id = :id AND activo = 1",
        ['id' => $id]
    );
    
    echo json_encode([
        'success' => true,
        'resident' => $resident,
        'contacts' => $contacts,
        'vehicles' => $vehicles
    ]);
}

// Crear nuevo residente
function createResident() {
    global $db;
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'Método no permitido']);
        return;
    }
    
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Validar datos requeridos
    $required = ['nombre', 'apellido', 'email', 'torre', 'apartamento'];
    foreach ($required as $field) {
        if (empty($data[$field])) {
            http_response_code(400);
            echo json_encode(['error' => "Campo requerido: $field"]);
            return;
        }
    }
    
    // Verificar email único
    $existingEmail = $db->queryOne(
        "SELECT id FROM residentes WHERE email = :email",
        ['email' => $data['email']]
    );
    
    if ($existingEmail) {
        http_response_code(400);
        echo json_encode(['error' => 'El email ya está registrado']);
        return;
    }
    
    // Verificar apartamento único por torre
    $existingUnit = $db->queryOne(
        "SELECT id FROM residentes WHERE torre = :torre AND apartamento = :apartamento AND estado != 'inactivo'",
        ['torre' => $data['torre'], 'apartamento' => $data['apartamento']]
    );
    
    if ($existingUnit) {
        http_response_code(400);
        echo json_encode(['error' => 'La unidad ya está ocupada']);
        return;
    }
    
    $db->beginTransaction();
    
    try {
        // Insertar residente
        $residentData = [
            'nombre' => $data['nombre'],
            'apellido' => $data['apellido'],
            'email' => $data['email'],
            'telefono' => $data['telefono'] ?? null,
            'telefono_emergencia' => $data['telefono_emergencia'] ?? null,
            'cedula' => $data['cedula'] ?? null,
            'fecha_nacimiento' => $data['fecha_nacimiento'] ?? null,
            'ocupacion' => $data['ocupacion'] ?? null,
            'torre' => $data['torre'],
            'apartamento' => $data['apartamento'],
            'area_apartamento' => $data['area_apartamento'] ?? null,
            'tipo_apartamento' => $data['tipo_apartamento'] ?? null,
            'estado' => $data['estado'] ?? 'pendiente',
            'nivel_acceso' => $data['nivel_acceso'] ?? 'ninguno',
            'es_propietario' => isset($data['es_propietario']) ? (bool)$data['es_propietario'] : false,
            'es_arrendatario' => isset($data['es_arrendatario']) ? (bool)$data['es_arrendatario'] : false,
            'fecha_inicio_residencia' => $data['fecha_inicio_residencia'] ?? null,
            'fecha_fin_residencia' => $data['fecha_fin_residencia'] ?? null,
            'observaciones' => $data['observaciones'] ?? null,
            'creado_por' => $_SESSION['user_id']
        ];
        
        $residentId = $db->insert('residentes', $residentData);
        
        // Registrar en historial
        $db->insert('historial_residentes', [
            'residente_id' => $residentId,
            'accion' => 'crear_residente',
            'descripcion' => 'Residente creado en el sistema',
            'datos_nuevos' => json_encode($residentData),
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'realizado_por' => $_SESSION['user_id']
        ]);
        
        // Si el estado es pendiente, crear solicitud automática
        if ($residentData['estado'] === 'pendiente') {
            $db->insert('solicitudes_residentes', [
                'residente_id' => $residentId,
                'tipo_solicitud' => 'activacion',
                'descripcion' => 'Solicitud automática de activación para nuevo residente',
                'prioridad' => 'media'
            ]);
        }
        
        $db->commit();
        
        echo json_encode([
            'success' => true,
            'message' => 'Residente creado exitosamente',
            'residente_id' => $residentId
        ]);
        
    } catch (Exception $e) {
        $db->rollback();
        error_log("Error creando residente: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Error al crear residente']);
    }
}

// Actualizar residente
function updateResident() {
    global $db;
    
    if ($_SERVER['REQUEST_METHOD'] !== 'PUT') {
        http_response_code(405);
        echo json_encode(['error' => 'Método no permitido']);
        return;
    }
    
    $id = (int)($_GET['id'] ?? 0);
    if (!$id) {
        http_response_code(400);
        echo json_encode(['error' => 'ID de residente requerido']);
        return;
    }
    
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Obtener datos actuales
    $currentResident = $db->queryOne(
        "SELECT * FROM residentes WHERE id = :id",
        ['id' => $id]
    );
    
    if (!$currentResident) {
        http_response_code(404);
        echo json_encode(['error' => 'Residente no encontrado']);
        return;
    }
    
    $db->beginTransaction();
    
    try {
        // Preparar datos para actualizar
        $updateData = [
            'nombre' => $data['nombre'] ?? $currentResident['nombre'],
            'apellido' => $data['apellido'] ?? $currentResident['apellido'],
            'email' => $data['email'] ?? $currentResident['email'],
            'telefono' => $data['telefono'] ?? $currentResident['telefono'],
            'telefono_emergencia' => $data['telefono_emergencia'] ?? $currentResident['telefono_emergencia'],
            'cedula' => $data['cedula'] ?? $currentResident['cedula'],
            'fecha_nacimiento' => $data['fecha_nacimiento'] ?? $currentResident['fecha_nacimiento'],
            'ocupacion' => $data['ocupacion'] ?? $currentResident['ocupacion'],
            'torre' => $data['torre'] ?? $currentResident['torre'],
            'apartamento' => $data['apartamento'] ?? $currentResident['apartamento'],
            'area_apartamento' => $data['area_apartamento'] ?? $currentResident['area_apartamento'],
            'tipo_apartamento' => $data['tipo_apartamento'] ?? $currentResident['tipo_apartamento'],
            'estado' => $data['estado'] ?? $currentResident['estado'],
            'nivel_acceso' => $data['nivel_acceso'] ?? $currentResident['nivel_acceso'],
            'es_propietario' => isset($data['es_propietario']) ? (bool)$data['es_propietario'] : (bool)$currentResident['es_propietario'],
            'es_arrendatario' => isset($data['es_arrendatario']) ? (bool)$data['es_arrendatario'] : (bool)$currentResident['es_arrendatario'],
            'fecha_inicio_residencia' => $data['fecha_inicio_residencia'] ?? $currentResident['fecha_inicio_residencia'],
            'fecha_fin_residencia' => $data['fecha_fin_residencia'] ?? $currentResident['fecha_fin_residencia'],
            'observaciones' => $data['observaciones'] ?? $currentResident['observaciones'],
            'modificado_por' => $_SESSION['user_id']
        ];
        
        $db->update('residentes', $updateData, ['id' => $id]);
        
        // Registrar en historial
        $db->insert('historial_residentes', [
            'residente_id' => $id,
            'accion' => 'actualizar_residente',
            'descripcion' => 'Información del residente actualizada',
            'datos_anteriores' => json_encode($currentResident),
            'datos_nuevos' => json_encode($updateData),
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'realizado_por' => $_SESSION['user_id']
        ]);
        
        $db->commit();
        
        echo json_encode([
            'success' => true,
            'message' => 'Residente actualizado exitosamente'
        ]);
        
    } catch (Exception $e) {
        $db->rollback();
        error_log("Error actualizando residente: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Error al actualizar residente']);
    }
}

// Eliminar residente
function deleteResident() {
    global $db;
    
    if ($_SERVER['REQUEST_METHOD'] !== 'DELETE') {
        http_response_code(405);
        echo json_encode(['error' => 'Método no permitido']);
        return;
    }
    
    $id = (int)($_GET['id'] ?? 0);
    if (!$id) {
        http_response_code(400);
        echo json_encode(['error' => 'ID de residente requerido']);
        return;
    }
    
    $resident = $db->queryOne(
        "SELECT * FROM residentes WHERE id = :id",
        ['id' => $id]
    );
    
    if (!$resident) {
        http_response_code(404);
        echo json_encode(['error' => 'Residente no encontrado']);
        return;
    }
    
    $db->beginTransaction();
    
    try {
        // Registrar en historial antes de eliminar
        $db->insert('historial_residentes', [
            'residente_id' => $id,
            'accion' => 'eliminar_residente',
            'descripcion' => 'Residente eliminado del sistema',
            'datos_anteriores' => json_encode($resident),
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'realizado_por' => $_SESSION['user_id']
        ]);
        
        // Eliminar residente (las tablas relacionadas se eliminan en cascada)
        $db->delete('residentes', ['id' => $id]);
        
        $db->commit();
        
        echo json_encode([
            'success' => true,
            'message' => 'Residente eliminado exitosamente'
        ]);
        
    } catch (Exception $e) {
        $db->rollback();
        error_log("Error eliminando residente: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Error al eliminar residente']);
    }
}

// Obtener solicitudes pendientes
function getPendingRequests() {
    global $db;
    
    $requests = $db->query(
        "SELECT s.*, 
                CONCAT(r.nombre, ' ', r.apellido) as residente_nombre,
                CONCAT(r.torre, '-', r.apartamento) as unidad,
                r.email as residente_email,
                u.username as procesado_por_usuario
         FROM solicitudes_residentes s
         JOIN residentes r ON s.residente_id = r.id
         LEFT JOIN usuarios u ON s.procesado_por = u.id
         WHERE s.estado = 'pendiente'
         ORDER BY s.prioridad DESC, s.fecha_solicitud ASC"
    );
    
    echo json_encode([
        'success' => true,
        'requests' => $requests
    ]);
}

// Aprobar solicitud
function approveRequest() {
    global $db;
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'Método no permitido']);
        return;
    }
    
    $data = json_decode(file_get_contents('php://input'), true);
    $requestId = (int)($data['request_id'] ?? 0);
    $observations = $data['observations'] ?? '';
    
    if (!$requestId) {
        http_response_code(400);
        echo json_encode(['error' => 'ID de solicitud requerido']);
        return;
    }
    
    $request = $db->queryOne(
        "SELECT * FROM solicitudes_residentes WHERE id = :id AND estado = 'pendiente'",
        ['id' => $requestId]
    );
    
    if (!$request) {
        http_response_code(404);
        echo json_encode(['error' => 'Solicitud no encontrada o ya procesada']);
        return;
    }
    
    $db->beginTransaction();
    
    try {
        // Actualizar solicitud
        $db->update('solicitudes_residentes', [
            'estado' => 'aprobada',
            'fecha_procesamiento' => date('Y-m-d H:i:s'),
            'procesado_por' => $_SESSION['user_id'],
            'observaciones_procesamiento' => $observations
        ], ['id' => $requestId]);
        
        // Aplicar cambios según tipo de solicitud
        switch($request['tipo_solicitud']) {
            case 'activacion':
                $db->update('residentes', [
                    'estado' => 'activo',
                    'nivel_acceso' => 'completo',
                    'fecha_ultima_actividad' => date('Y-m-d H:i:s')
                ], ['id' => $request['residente_id']]);
                break;
                
            case 'reactivacion':
                $db->update('residentes', [
                    'estado' => 'activo',
                    'fecha_ultima_actividad' => date('Y-m-d H:i:s')
                ], ['id' => $request['residente_id']]);
                break;
        }
        
        // Registrar en historial
        $db->insert('historial_residentes', [
            'residente_id' => $request['residente_id'],
            'accion' => 'aprobar_solicitud',
            'descripcion' => "Solicitud {$request['tipo_solicitud']} aprobada",
            'datos_nuevos' => json_encode(['solicitud_id' => $requestId, 'observaciones' => $observations]),
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'realizado_por' => $_SESSION['user_id']
        ]);
        
        $db->commit();
        
        echo json_encode([
            'success' => true,
            'message' => 'Solicitud aprobada exitosamente'
        ]);
        
    } catch (Exception $e) {
        $db->rollback();
        error_log("Error aprobando solicitud: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Error al aprobar solicitud']);
    }
}

// Rechazar solicitud
function rejectRequest() {
    global $db;
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'Método no permitido']);
        return;
    }
    
    $data = json_decode(file_get_contents('php://input'), true);
    $requestId = (int)($data['request_id'] ?? 0);
    $observations = $data['observations'] ?? '';
    
    if (!$requestId) {
        http_response_code(400);
        echo json_encode(['error' => 'ID de solicitud requerido']);
        return;
    }
    
    $request = $db->queryOne(
        "SELECT * FROM solicitudes_residentes WHERE id = :id AND estado = 'pendiente'",
        ['id' => $requestId]
    );
    
    if (!$request) {
        http_response_code(404);
        echo json_encode(['error' => 'Solicitud no encontrada o ya procesada']);
        return;
    }
    
    $db->beginTransaction();
    
    try {
        // Actualizar solicitud
        $db->update('solicitudes_residentes', [
            'estado' => 'rechazada',
            'fecha_procesamiento' => date('Y-m-d H:i:s'),
            'procesado_por' => $_SESSION['user_id'],
            'observaciones_procesamiento' => $observations
        ], ['id' => $requestId]);
        
        // Registrar en historial
        $db->insert('historial_residentes', [
            'residente_id' => $request['residente_id'],
            'accion' => 'rechazar_solicitud',
            'descripcion' => "Solicitud {$request['tipo_solicitud']} rechazada",
            'datos_nuevos' => json_encode(['solicitud_id' => $requestId, 'observaciones' => $observations]),
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'realizado_por' => $_SESSION['user_id']
        ]);
        
        $db->commit();
        
        echo json_encode([
            'success' => true,
            'message' => 'Solicitud rechazada exitosamente'
        ]);
        
    } catch (Exception $e) {
        $db->rollback();
        error_log("Error rechazando solicitud: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Error al rechazar solicitud']);
    }
}

// Filtrar residentes (similar a list pero con filtros específicos)
function filterResidents() {
    getResidents(); // Reutilizar la función de listar con filtros
}
?>