<?php
/**
 * Archivo: /var/www/html/includes/index.php
 * Documentación e información del sistema SKYN3T
 */

// Definir constante del sistema
define('SKYN3T_SYSTEM', true);

// Incluir archivos del sistema
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/session.php';

// Configurar headers
header('Content-Type: text/html; charset=UTF-8');

// Verificar si es una petición de información del sistema
if (isset($_GET['info']) && $_GET['info'] === 'system') {
    header('Content-Type: application/json');
    echo json_encode(getSystemInfo());
    exit;
}

// Verificar si es una petición de salud del sistema
if (isset($_GET['health'])) {
    header('Content-Type: application/json');
    
    $health = [
        'status' => 'ok',
        'timestamp' => date('Y-m-d H:i:s'),
        'components' => []
    ];
    
    // Verificar base de datos
    try {
        $db = Database::getInstance();
        $dbInfo = $db->getDatabaseInfo();
        $health['components']['database'] = [
            'status' => 'healthy',
            'version' => $dbInfo['version'],
            'tables_count' => $dbInfo['tables_count']
        ];
    } catch (Exception $e) {
        $health['components']['database'] = [
            'status' => 'unhealthy',
            'error' => $e->getMessage()
        ];
        $health['status'] = 'error';
    }
    
    // Verificar sesiones
    try {
        $sessionManager = getSessionManager();
        $sessionStats = $sessionManager->getSessionStats();
        $health['components']['sessions'] = [
            'status' => 'healthy',
            'active_sessions' => $sessionStats['active_sessions'],
            'unique_users' => $sessionStats['unique_users']
        ];
    } catch (Exception $e) {
        $health['components']['sessions'] = [
            'status' => 'unhealthy',
            'error' => $e->getMessage()
        ];
        $health['status'] = 'error';
    }
    
    // Verificar archivos críticos
    $integrity = Security::verifyFileIntegrity();
    $missingFiles = array_filter($integrity, function($file) {
        return !$file['exists'];
    });
    
    $health['components']['files'] = [
        'status' => empty($missingFiles) ? 'healthy' : 'unhealthy',
        'checked_files' => count($integrity),
        'missing_files' => count($missingFiles)
    ];
    
    if (!empty($missingFiles)) {
        $health['status'] = 'warning';
    }
    
    echo json_encode($health);
    exit;
}

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SKYN3T - Sistema de Archivos Core</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            min-height: 100vh;
            padding: 20px;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #111;
            padding: 30px;
            border-radius: 10px;
            border: 1px solid #333;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.1);
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 1px solid #333;
            padding-bottom: 20px;
        }
        
        .header h1 {
            font-size: 2.5em;
            color: #00ff00;
            text-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
            margin-bottom: 10px;
        }
        
        .header p {
            color: #888;
            font-size: 1.1em;
        }
        
        .section {
            margin-bottom: 30px;
            background: #0f0f0f;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #00ff00;
        }
        
        .section h2 {
            color: #00ff00;
            margin-bottom: 15px;
            font-size: 1.5em;
        }
        
        .file-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
        }
        
        .file-item {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #333;
            transition: all 0.3s ease;
        }
        
        .file-item:hover {
            border-color: #00ff00;
            box-shadow: 0 0 10px rgba(0, 255, 0, 0.2);
        }
        
        .file-name {
            color: #00ff00;
            font-weight: bold;
            margin-bottom: 8px;
        }
        
        .file-desc {
            color: #ccc;
            font-size: 0.9em;
            margin-bottom: 10px;
        }
        
        .file-status {
            font-size: 0.8em;
            padding: 2px 8px;
            border-radius: 4px;
            display: inline-block;
        }
        
        .status-ok {
            background: #004400;
            color: #00ff00;
        }
        
        .status-error {
            background: #440000;
            color: #ff4444;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        
        .stat-box {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #333;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2em;
            color: #00ff00;
            font-weight: bold;
        }
        
        .stat-label {
            color: #888;
            font-size: 0.9em;
            margin-top: 5px;
        }
        
        .api-endpoints {
            background: #0f0f0f;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #333;
        }
        
        .endpoint {
            margin-bottom: 10px;
            padding: 8px;
            background: #1a1a1a;
            border-radius: 4px;
        }
        
        .endpoint-method {
            color: #ffff00;
            font-weight: bold;
            margin-right: 10px;
        }
        
        .endpoint-url {
            color: #00ffff;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #333;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SKYN3T CORE SYSTEM</h1>
            <p>Sistema de Archivos Core - Documentación e Información</p>
        </div>

        <!-- Información del Sistema -->
        <div class="section">
            <h2>📊 Información del Sistema</h2>
            <div class="stats-grid">
                <?php
                $systemInfo = getSystemInfo();
                ?>
                <div class="stat-box">
                    <div class="stat-value"><?php echo $systemInfo['version']; ?></div>
                    <div class="stat-label">Versión</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value"><?php echo $systemInfo['environment']; ?></div>
                    <div class="stat-label">Entorno</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value"><?php echo $systemInfo['debug_mode'] ? 'ON' : 'OFF'; ?></div>
                    <div class="stat-label">Debug Mode</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value"><?php echo $systemInfo['server_ip']; ?></div>
                    <div class="stat-label">Server IP</div>
                </div>
            </div>
        </div>

        <!-- Archivos del Sistema -->
        <div class="section">
            <h2>📁 Archivos Core del Sistema</h2>
            <div class="file-list">
                <?php
                $coreFiles = [
                    'config.php' => 'Configuraciones generales del sistema',
                    'database.php' => 'Conexión y manejo de base de datos',
                    'auth.php' => 'Sistema de autenticación',
                    'security.php' => 'Funciones de seguridad',
                    'session.php' => 'Manejo avanzado de sesiones'
                ];
                
                foreach ($coreFiles as $file => $description) {
                    $filePath = __DIR__ . '/' . $file;
                    $exists = file_exists($filePath);
                    $statusClass = $exists ? 'status-ok' : 'status-error';
                    $statusText = $exists ? 'OK' : 'ERROR';
                    
                    echo '<div class="file-item">';
                    echo '<div class="file-name">' . htmlspecialchars($file) . '</div>';
                    echo '<div class="file-desc">' . htmlspecialchars($description) . '</div>';
                    echo '<span class="file-status ' . $statusClass . '">' . $statusText . '</span>';
                    if ($exists) {
                        $size = round(filesize($filePath) / 1024, 2);
                        echo '<span style="margin-left: 10px; color: #666; font-size: 0.8em;">' . $size . ' KB</span>';
                    }
                    echo '</div>';
                }
                ?>
            </div>
        </div>

        <!-- Estado de la Base de Datos -->
        <div class="section">
            <h2>🗄️ Estado de la Base de Datos</h2>
            <?php
            try {
                $db = Database::getInstance();
                $dbInfo = $db->getDatabaseInfo();
                ?>
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="stat-value">✅</div>
                        <div class="stat-label">Conexión</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value"><?php echo $dbInfo['tables_count']; ?></div>
                        <div class="stat-label">Tablas</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value"><?php echo $dbInfo['database']; ?></div>
                        <div class="stat-label">Base de Datos</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value"><?php echo explode('-', $dbInfo['version'])[0]; ?></div>
                        <div class="stat-label">Versión</div>
                    </div>
                </div>
                <?php
            } catch (Exception $e) {
                echo '<div style="color: #ff4444; padding: 15px; background: #220000; border-radius: 6px;">';
                echo '<strong>Error de conexión:</strong> ' . htmlspecialchars($e->getMessage());
                echo '</div>';
            }
            ?>
        </div>

        <!-- Estadísticas de Sesiones -->
        <div class="section">
            <h2>🔐 Estado de Sesiones</h2>
            <?php
            try {
                $sessionManager = getSessionManager();
                $sessionStats = $sessionManager->getSessionStats();
                ?>
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="stat-value"><?php echo $sessionStats['active_sessions']; ?></div>
                        <div class="stat-label">Sesiones Activas</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value"><?php echo $sessionStats['unique_users']; ?></div>
                        <div class="stat-label">Usuarios Únicos</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value"><?php echo $sessionStats['recent_logins_24h']; ?></div>
                        <div class="stat-label">Logins (24h)</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value"><?php echo round($sessionStats['avg_duration_minutes']); ?>m</div>
                        <div class="stat-label">Duración Promedio</div>
                    </div>
                </div>
                <?php
            } catch (Exception $e) {
                echo '<div style="color: #ff4444; padding: 15px; background: #220000; border-radius: 6px;">';
                echo '<strong>Error en sesiones:</strong> ' . htmlspecialchars($e->getMessage());
                echo '</div>';
            }
            ?>
        </div>

        <!-- Endpoints de API -->
        <div class="section">
            <h2>🔌 Endpoints de API Disponibles</h2>
            <div class="api-endpoints">
                <div class="endpoint">
                    <span class="endpoint-method">GET</span>
                    <span class="endpoint-url">/includes/?info=system</span>
                    <span style="color: #888; margin-left: 15px;">- Información del sistema (JSON)</span>
                </div>
                <div class="endpoint">
                    <span class="endpoint-method">GET</span>
                    <span class="endpoint-url">/includes/?health</span>
                    <span style="color: #888; margin-left: 15px;">- Estado de salud del sistema (JSON)</span>
                </div>
                <div class="endpoint">
                    <span class="endpoint-method">POST</span>
                    <span class="endpoint-url">/includes/database.php</span>
                    <span style="color: #888; margin-left: 15px;">- Test de conexión de BD</span>
                </div>
            </div>
        </div>

        <!-- Jerarquía de Roles -->
        <div class="section">
            <h2>👥 Jerarquía de Roles del Sistema</h2>
            <div class="file-list">
                <?php
                global $ROLE_HIERARCHY;
                $roles = [
                    'SuperUser' => 'Acceso total al sistema y administración',
                    'Admin' => 'Gestión de dispositivos y usuarios',
                    'SupportAdmin' => 'Soporte técnico y visualización',
                    'User' => 'Funcionalidades básicas de usuario'
                ];
                
                foreach ($roles as $role => $description) {
                    $level = getRoleLevel($role);
                    echo '<div class="file-item">';
                    echo '<div class="file-name">' . $role . ' (Nivel ' . $level . ')</div>';
                    echo '<div class="file-desc">' . $description . '</div>';
                    echo '</div>';
                }
                ?>
            </div>
        </div>

        <div class="footer">
            <p><?php echo getConfig('SYSTEM_COPYRIGHT'); ?> | Generado el <?php echo date('Y-m-d H:i:s'); ?></p>
        </div>
    </div>

    <script>
        // Auto-refresh cada 30 segundos
        setTimeout(function() {
            window.location.reload();
        }, 30000);
        
        console.log('SKYN3T Core System - Includes Directory');
        console.log('System Version:', '<?php echo getConfig("SYSTEM_VERSION"); ?>');
        console.log('Environment:', '<?php echo getConfig("ENVIRONMENT"); ?>');
    </script>
</body>
</html>
