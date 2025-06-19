<?php
/**
 * SKYN3T - API temporal de dispositivos
 * Versión: 2.3.0
 */

session_start();
header('Content-Type: application/json');

// Verificar autenticación
if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
    http_response_code(401);
    echo json_encode(['error' => 'No autorizado']);
    exit;
}

// Simular datos de dispositivos
$devices = [
    [
        'id' => '1',
        'name' => 'Relé Principal',
        'type' => 'relay_controller',
        'location' => 'Sala Principal',
        'status' => 'online',
        'ip' => '192.168.4.1'
    ],
    [
        'id' => '2',
        'name' => 'Sensor Temperatura',
        'type' => 'sensor',
        'location' => 'Sala Servidor',
        'status' => 'online',
        'ip' => '192.168.4.10'
    ],
    [
        'id' => '3',
        'name' => 'Cámara Entrada',
        'type' => 'camera',
        'location' => 'Entrada Principal',
        'status' => 'offline',
        'ip' => '192.168.4.20'
    ]
];

$action = $_GET['action'] ?? 'list';

if ($action === 'list') {
    echo json_encode(['devices' => $devices]);
} elseif ($action === 'stats' && isset($_GET['device_id'])) {
    // Simular estadísticas del dispositivo
    $stats = [
        'uptime' => '99.8%',
        'temperature' => '24°C',
        'memory' => '62%',
        'last_activation' => date('H:i', strtotime('-45 minutes')),
        'activations_today' => rand(5, 15)
    ];
    echo json_encode($stats);
} else {
    echo json_encode(['error' => 'Acción no válida']);
}
?>
