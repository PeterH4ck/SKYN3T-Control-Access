<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#137DC5">
    <title>Sistema Dashboard - SKYN3T</title>
    
    <style>
        /* Reset y Variables */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary-color: #2199ea;
            --secondary-color: #137DC5;
            --success-color: #28a745;
            --warning-color: #ffc107;
            --danger-color: #dc3545;
            --dark-bg: #222831;
            --glass-bg: rgba(55, 65, 79, 0.16);
            --glass-border: rgba(33, 153, 234, 0.22);
            --text-light: rgba(255, 255, 255, 0.9);
            --text-dim: rgba(255, 255, 255, 0.6);
        }

        /* Base */
        html, body {
            height: 100%;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
            background-color: var(--dark-bg);
            color: var(--text-light);
        }

        body {
            display: flex;
            flex-direction: column;
        }

        /* Fondo */
        .background {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: url('/images/login-background.jpeg') center/cover;
            filter: blur(2px);
            transform: scale(1.1);
            z-index: 0;
        }

        /* Container principal */
        .main-container {
            position: relative;
            z-index: 1;
            flex: 1;
            overflow-y: auto;
            padding: 100px 20px 20px;
        }

        /* Logo flotante */
        .floating-logo {
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            z-index: 10;
            pointer-events: none;
        }

        .logo-img {
            max-width: 150px;
            height: auto;
            filter: drop-shadow(0 0 20px rgba(19, 125, 197, 0.8));
        }

        /* Botones flotantes */
        .floating-button {
            position: fixed;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.3s ease;
            z-index: 10;
            background: var(--glass-bg);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 2px solid var(--glass-border);
            color: var(--primary-color);
            text-decoration: none;
            font-size: 1.2rem;
        }

        .floating-button:hover {
            transform: scale(1.1);
            box-shadow: 0 5px 20px rgba(33, 153, 234, 0.3);
        }

        .btn-back {
            top: 20px;
            left: 20px;
        }

        .btn-refresh {
            top: 20px;
            right: 20px;
        }

        /* Dashboard Grid */
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }

        /* Cards */
        .card {
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 2px solid var(--glass-border);
            border-radius: 20px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(19, 125, 197, 0.1);
            transition: all 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(19, 125, 197, 0.2);
        }

        .card-header {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }

        .card-icon {
            width: 50px;
            height: 50px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            margin-right: 15px;
        }

        .card-icon.success {
            background: rgba(40, 167, 69, 0.2);
            color: var(--success-color);
        }

        .card-icon.info {
            background: rgba(33, 153, 234, 0.2);
            color: var(--primary-color);
        }

        .card-icon.warning {
            background: rgba(255, 193, 7, 0.2);
            color: var(--warning-color);
        }

        .card-icon.danger {
            background: rgba(220, 53, 69, 0.2);
            color: var(--danger-color);
        }

        .card-title {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-light);
        }

        .card-subtitle {
            font-size: 0.85rem;
            color: var(--text-dim);
        }

        .card-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary-color);
            margin: 15px 0;
        }

        /* Stats List */
        .stats-list {
            list-style: none;
        }

        .stat-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .stat-item:last-child {
            border-bottom: none;
        }

        .stat-label {
            color: var(--text-dim);
            font-size: 0.9rem;
        }

        .stat-value {
            color: var(--text-light);
            font-weight: 600;
        }

        /* Status Badge */
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }

        .status-badge.active {
            background: rgba(40, 167, 69, 0.2);
            color: var(--success-color);
        }

        .status-badge.inactive {
            background: rgba(220, 53, 69, 0.2);
            color: var(--danger-color);
        }

        /* Info Tables */
        .info-table {
            width: 100%;
            margin-top: 20px;
        }

        .info-table td {
            padding: 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .info-table td:first-child {
            color: var(--text-dim);
            width: 40%;
        }

        .info-table td:last-child {
            color: var(--text-light);
            font-family: monospace;
        }

        /* Loading State */
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid var(--glass-border);
            border-top: 2px solid var(--primary-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 20px;
            color: var(--text-dim);
            font-size: 0.85rem;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .main-container {
                padding: 80px 15px 15px;
            }

            .dashboard-grid {
                grid-template-columns: 1fr;
            }

            .card {
                padding: 20px;
            }

            .card-value {
                font-size: 1.5rem;
            }

            .floating-logo {
                top: 15px;
            }

            .logo-img {
                max-width: 120px;
            }

            .floating-button {
                width: 45px;
                height: 45px;
                font-size: 1rem;
            }
        }
    </style>
</head>
<body>
    <!-- Fondo -->
    <div class="background"></div>

    <!-- Logo flotante -->
    <div class="floating-logo">
        <img src="/images/logo.png" alt="SKYN3T" class="logo-img">
    </div>

    <!-- Botones flotantes -->
    <a href="/" class="floating-button btn-back" title="Volver">
        <span>←</span>
    </a>

    <button class="floating-button btn-refresh" onclick="location.reload()" title="Actualizar">
        <span>↻</span>
    </button>

    <!-- Container principal -->
    <div class="main-container">
        <div class="dashboard-grid">
            <!-- Card: Sistema -->
            <div class="card">
                <div class="card-header">
                    <div class="card-icon info">⚙</div>
                    <div>
                        <h3 class="card-title">Información del Sistema</h3>
                        <p class="card-subtitle">Estado general</p>
                    </div>
                </div>
                <table class="info-table">
                    <tr>
                        <td>Versión</td>
                        <td id="system-version">Cargando...</td>
                    </tr>
                    <tr>
                        <td>Entorno</td>
                        <td id="system-env">Cargando...</td>
                    </tr>
                    <tr>
                        <td>PHP</td>
                        <td id="php-version">Cargando...</td>
                    </tr>
                    <tr>
                        <td>Base de Datos</td>
                        <td id="db-version">Cargando...</td>
                    </tr>
                    <tr>
                        <td>Uptime</td>
                        <td id="system-uptime">Cargando...</td>
                    </tr>
                </table>
            </div>

            <!-- Card: Base de Datos -->
            <div class="card">
                <div class="card-header">
                    <div class="card-icon success">🗄</div>
                    <div>
                        <h3 class="card-title">Base de Datos</h3>
                        <p class="card-subtitle">MariaDB</p>
                    </div>
                </div>
                <div class="card-value" id="db-status">
                    <span class="loading"></span>
                </div>
                <ul class="stats-list">
                    <li class="stat-item">
                        <span class="stat-label">Conexión</span>
                        <span class="stat-value" id="db-connection">-</span>
                    </li>
                    <li class="stat-item">
                        <span class="stat-label">Tablas</span>
                        <span class="stat-value" id="db-tables">-</span>
                    </li>
                    <li class="stat-item">
                        <span class="stat-label">Tamaño</span>
                        <span class="stat-value" id="db-size">-</span>
                    </li>
                </ul>
            </div>

            <!-- Card: Sesiones -->
            <div class="card">
                <div class="card-header">
                    <div class="card-icon info">👥</div>
                    <div>
                        <h3 class="card-title">Sesiones</h3>
                        <p class="card-subtitle">Usuarios activos</p>
                    </div>
                </div>
                <div class="card-value" id="active-sessions">0</div>
                <ul class="stats-list">
                    <li class="stat-item">
                        <span class="stat-label">Usuarios únicos</span>
                        <span class="stat-value" id="unique-users">0</span>
                    </li>
                    <li class="stat-item">
                        <span class="stat-label">Sesiones hoy</span>
                        <span class="stat-value" id="sessions-today">0</span>
                    </li>
                    <li class="stat-item">
                        <span class="stat-label">Duración promedio</span>
                        <span class="stat-value" id="avg-duration">0m</span>
                    </li>
                </ul>
            </div>

            <!-- Card: Relé -->
            <div class="card">
                <div class="card-header">
                    <div class="card-icon warning">🔌</div>
                    <div>
                        <h3 class="card-title">Estado del Relé</h3>
                        <p class="card-subtitle">Control principal</p>
                    </div>
                </div>
                <div class="card-value" id="relay-status">
                    <span class="loading"></span>
                </div>
                <ul class="stats-list">
                    <li class="stat-item">
                        <span class="stat-label">GPIO Pin</span>
                        <span class="stat-value">23</span>
                    </li>
                    <li class="stat-item">
                        <span class="stat-label">Último cambio</span>
                        <span class="stat-value" id="relay-last-change">-</span>
                    </li>
                    <li class="stat-item">
                        <span class="stat-label">Cambios hoy</span>
                        <span class="stat-value" id="relay-changes">0</span>
                    </li>
                </ul>
            </div>

            <!-- Card: Actividad -->
            <div class="card">
                <div class="card-header">
                    <div class="card-icon danger">📊</div>
                    <div>
                        <h3 class="card-title">Actividad</h3>
                        <p class="card-subtitle">Últimas 24 horas</p>
                    </div>
                </div>
                <ul class="stats-list">
                    <li class="stat-item">
                        <span class="stat-label">Logins</span>
                        <span class="stat-value" id="logins-24h">0</span>
                    </li>
                    <li class="stat-item">
                        <span class="stat-label">Acciones</span>
                        <span class="stat-value" id="actions-24h">0</span>
                    </li>
                    <li class="stat-item">
                        <span class="stat-label">Errores</span>
                        <span class="stat-value" id="errors-24h">0</span>
                    </li>
                    <li class="stat-item">
                        <span class="stat-label">Alertas</span>
                        <span class="stat-value" id="alerts-24h">0</span>
                    </li>
                </ul>
            </div>

            <!-- Card: Recursos -->
            <div class="card">
                <div class="card-header">
                    <div class="card-icon success">💻</div>
                    <div>
                        <h3 class="card-title">Recursos del Sistema</h3>
                        <p class="card-subtitle">Uso actual</p>
                    </div>
                </div>
                <ul class="stats-list">
                    <li class="stat-item">
                        <span class="stat-label">CPU Load</span>
                        <span class="stat-value" id="cpu-load">-</span>
                    </li>
                    <li class="stat-item">
                        <span class="stat-label">Memoria</span>
                        <span class="stat-value" id="memory-usage">-</span>
                    </li>
                    <li class="stat-item">
                        <span class="stat-label">Disco</span>
                        <span class="stat-value" id="disk-usage">-</span>
                    </li>
                    <li class="stat-item">
                        <span class="stat-label">Temperatura</span>
                        <span class="stat-value" id="cpu-temp">-</span>
                    </li>
                </ul>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <div class="footer">
        <p>SKYN3T - Sistema de Control y Monitoreo v2.0.0</p>
        <p>© 2025 IT & NETWORK SOLUTIONS</p>
    </div>

    <script>
        // Configuración
        const API_ENDPOINT = '?info=all';
        const REFRESH_INTERVAL = 5000; // 5 segundos

        // Estado
        let isLoading = false;

        // Obtener información del sistema
        async function fetchSystemInfo() {
            if (isLoading) return;
            isLoading = true;

            try {
                const response = await fetch(API_ENDPOINT);
                const data = await response.json();

                if (data.success) {
                    updateDashboard(data);
                }
            } catch (error) {
                console.error('Error fetching system info:', error);
            } finally {
                isLoading = false;
            }
        }

        // Actualizar dashboard
        function updateDashboard(data) {
            // Sistema
            updateElement('system-version', data.system.version);
            updateElement('system-env', data.system.environment);
            updateElement('php-version', data.system.php_version);
            updateElement('db-version', data.database.version);
            updateElement('system-uptime', formatUptime(data.system.uptime));

            // Base de datos
            updateElement('db-status', data.database.status.toUpperCase());
            updateElement('db-connection', data.database.connected ? 'Activa' : 'Error');
            updateElement('db-tables', data.database.tables_count);
            updateElement('db-size', data.database.size || 'N/A');

            // Sesiones
            updateElement('active-sessions', data.sessions.active);
            updateElement('unique-users', data.sessions.unique_users);
            updateElement('sessions-today', data.sessions.today);
            updateElement('avg-duration', data.sessions.avg_duration + 'm');

            // Relé
            const relayStatus = data.relay.state === 1 ? 'ENCENDIDO' : 'APAGADO';
            const relayColor = data.relay.state === 1 ? '#28a745' : '#dc3545';
            const relayElement = document.getElementById('relay-status');
            if (relayElement) {
                relayElement.textContent = relayStatus;
                relayElement.style.color = relayColor;
            }
            updateElement('relay-last-change', formatTime(data.relay.last_change));
            updateElement('relay-changes', data.relay.changes_today || 0);

            // Actividad
            updateElement('logins-24h', data.activity.logins_24h || 0);
            updateElement('actions-24h', data.activity.actions_24h || 0);
            updateElement('errors-24h', data.activity.errors_24h || 0);
            updateElement('alerts-24h', data.activity.alerts_24h || 0);

            // Recursos
            updateElement('cpu-load', data.resources.cpu_load || 'N/A');
            updateElement('memory-usage', data.resources.memory_usage || 'N/A');
            updateElement('disk-usage', data.resources.disk_usage || 'N/A');
            updateElement('cpu-temp', data.resources.cpu_temp || 'N/A');
        }

        // Actualizar elemento
        function updateElement(id, value) {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
            }
        }

        // Formatear uptime
        function formatUptime(seconds) {
            if (!seconds) return 'N/A';
            
            const days = Math.floor(seconds / 86400);
            const hours = Math.floor((seconds % 86400) / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);

            if (days > 0) {
                return `${days}d ${hours}h ${minutes}m`;
            } else if (hours > 0) {
                return `${hours}h ${minutes}m`;
            } else {
                return `${minutes}m`;
            }
        }

        // Formatear tiempo
        function formatTime(timestamp) {
            if (!timestamp) return 'N/A';
            
            const date = new Date(timestamp);
            const now = new Date();
            const diff = now - date;
            
            if (diff < 60000) {
                return 'Hace un momento';
            } else if (diff < 3600000) {
                const mins = Math.floor(diff / 60000);
                return `Hace ${mins} min`;
            } else if (diff < 86400000) {
                const hours = Math.floor(diff / 3600000);
                return `Hace ${hours}h`;
            } else {
                return date.toLocaleDateString();
            }
        }

        // Inicializar
        document.addEventListener('DOMContentLoaded', () => {
            fetchSystemInfo();
            
            // Actualizar periódicamente
            setInterval(fetchSystemInfo, REFRESH_INTERVAL);
        });
    </script>
</body>
</html>

<?php
// PHP Backend para proveer datos
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/session.php';

// Solo responder a peticiones con parámetro info
if (isset($_GET['info'])) {
    header('Content-Type: application/json');
    
    try {
        $db = Database::getInstance();
        $sessionManager = SessionManager::getInstance();
        
        $response = ['success' => true];
        
        // Información del sistema
        $response['system'] = [
            'version' => SYSTEM_VERSION,
            'environment' => ENVIRONMENT,
            'php_version' => PHP_VERSION,
            'uptime' => time() - $_SERVER['REQUEST_TIME']
        ];
        
        // Información de base de datos
        $dbInfo = $db->getDatabaseInfo();
        $response['database'] = [
            'status' => $db->isConnected() ? 'online' : 'offline',
            'connected' => $db->isConnected(),
            'version' => $dbInfo['version'] ?? 'Unknown',
            'tables_count' => $dbInfo['tables_count'] ?? 0
        ];
        
        // Estadísticas de sesiones
        $sessionStats = $sessionManager->getSessionStats();
        $response['sessions'] = [
            'active' => $sessionStats['active_sessions'] ?? 0,
            'unique_users' => $sessionStats['unique_users'] ?? 0,
            'today' => $sessionStats['sessions_today'] ?? 0,
            'avg_duration' => $sessionStats['avg_session_duration'] ?? 0
        ];
        
        // Estado del relé
        $relayStatus = get_relay_status();
        $response['relay'] = [
            'state' => $relayStatus['relay_state'] ?? 0,
            'last_change' => $relayStatus['timestamp'] ?? null,
            'changed_by' => $relayStatus['changed_by'] ?? 'Unknown'
        ];
        
        // Estadísticas de actividad
        $stmt = $db->execute("
            SELECT 
                SUM(CASE WHEN action = 'login' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 ELSE 0 END) as logins_24h,
                SUM(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 ELSE 0 END) as actions_24h,
                SUM(CASE WHEN action LIKE '%error%' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 ELSE 0 END) as errors_24h,
                SUM(CASE WHEN action LIKE '%alert%' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 ELSE 0 END) as alerts_24h
            FROM " . TABLE_ACCESS_LOG
        );
        $activity = $stmt->fetch();
        $response['activity'] = $activity ?: [];
        
        // Recursos del sistema (simulados por ahora)
        $response['resources'] = [
            'cpu_load' => '15%',
            'memory_usage' => '45%',
            'disk_usage' => '32%',
            'cpu_temp' => '42°C'
        ];
        
        echo json_encode($response);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => ENVIRONMENT === 'development' ? $e->getMessage() : 'Internal error'
        ]);
    }
    exit;
}
?>
