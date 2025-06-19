<?php
session_start();
header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'No autorizado']);
    exit;
}

$action = $_GET['action'] ?? '';

switch($action) {
    case 'list':
        $devices = [
            [
                'id' => 'ctrl_001',
                'name' => 'Controlador Principal',
                'type' => 'relay_controller',
                'status' => 'online',
                'location' => 'Edificio A - Planta 1',
                'ip' => '192.168.1.100'
            ],
            [
                'id' => 'ctrl_002', 
                'name' => 'Controlador Secundario',
                'type' => 'relay_controller',
                'status' => 'online',
                'location' => 'Edificio B - Planta 2',
                'ip' => '192.168.1.101'
            ],
            [
                'id' => 'sensor_001',
                'name' => 'Sensor Temperatura',
                'type' => 'temperature_sensor',
                'status' => 'online', 
                'location' => 'Sala de Servidores',
                'ip' => '192.168.1.102'
            ]
        ];
        
        echo json_encode(['devices' => $devices]);
        break;
        
    case 'stats':
        $device_id = $_GET['device_id'] ?? '';
        
        $stats = [
            'ctrl_001' => [
                'uptime' => '99.8%',
                'temperature' => '23°C',
                'memory' => '64%',
                'network_latency' => '8ms',
                'last_activation' => '14:32',
                'activations_today' => 12
            ],
            'ctrl_002' => [
                'uptime' => '99.2%', 
                'temperature' => '26°C',
                'memory' => '72%',
                'network_latency' => '15ms',
                'last_activation' => '13:45',
                'activations_today' => 8
            ],
            'sensor_001' => [
                'uptime' => '99.9%',
                'temperature' => '22°C', 
                'memory' => '45%',
                'network_latency' => '5ms',
                'last_reading' => '14:35',
                'readings_today' => 1440
            ]
        ];
        
        echo json_encode($stats[$device_id] ?? ['error' => 'Dispositivo no encontrado']);
        break;
        
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Acción no válida']);
}
?>