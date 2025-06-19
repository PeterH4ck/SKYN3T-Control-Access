<?php
// Archivo: /var/www/html/mobile_test.php
// Página de prueba para verificar login desde móvil

header('Content-Type: text/html; charset=UTF-8');
header('Access-Control-Allow-Origin: *');

// Obtener IP del servidor
$server_ip = $_SERVER['SERVER_ADDR'] ?? 'unknown';
$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test de Login Móvil</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f0f0f0;
        }
        .container {
            max-width: 400px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            font-size: 24px;
        }
        .info-box {
            background: #e8f4f8;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .test-form {
            margin: 20px 0;
        }
        input {
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
            font-size: 16px;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 18px;
            cursor: pointer;
        }
        button:hover {
            background: #2980b9;
        }
        #result {
            margin-top: 20px;
            padding: 15px;
            border-radius: 5px;
            display: none;
        }
        .success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .loading {
            text-align: center;
            color: #666;
        }
        .api-test {
            margin: 20px 0;
        }
        .test-button {
            background: #27ae60;
            margin: 5px 0;
        }
        .test-button:hover {
            background: #229954;
        }
        pre {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Test de Login Móvil</h1>
        
        <div class="info-box">
            <strong>Información de Conexión:</strong><br>
            📱 Tu IP: <?php echo htmlspecialchars($client_ip); ?><br>
            🖥️ IP Servidor: <?php echo htmlspecialchars($server_ip); ?><br>
            📅 Fecha/Hora: <?php echo date('Y-m-d H:i:s'); ?>
        </div>
        
        <div class="api-test">
            <h3>1. Test de Conectividad</h3>
            <button class="test-button" onclick="testConnection()">Probar Conexión</button>
            <div id="connection-result"></div>
        </div>
        
        <div class="api-test">
            <h3>2. Test de Base de Datos</h3>
            <button class="test-button" onclick="testDatabase()">Probar Base de Datos</button>
            <div id="database-result"></div>
        </div>
        
        <div class="test-form">
            <h3>3. Test de Login</h3>
            <form id="test-login-form">
                <input type="text" id="username" placeholder="Usuario" value="admin" required>
                <input type="password" id="password" placeholder="Contraseña" value="admin" required>
                <button type="submit">Probar Login</button>
            </form>
            <div id="login-result"></div>
        </div>
        
        <div id="result"></div>
    </div>
    
    <script>
        // Test de conectividad básica
        async function testConnection() {
            const resultDiv = document.getElementById('connection-result');
            resultDiv.innerHTML = '<div class="loading">Probando conexión...</div>';
            
            try {
                const response = await fetch('/test_connection.php');
                const data = await response.json();
                resultDiv.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            } catch (error) {
                resultDiv.innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        }
        
        // Test de base de datos
        async function testDatabase() {
            const resultDiv = document.getElementById('database-result');
            resultDiv.innerHTML = '<div class="loading">Probando base de datos...</div>';
            
            try {
                const response = await fetch('/api/test_db.php');
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                const text = await response.text();
                resultDiv.innerHTML = '<pre>' + text + '</pre>';
            } catch (error) {
                resultDiv.innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        }
        
        // Test de login
        document.getElementById('test-login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const resultDiv = document.getElementById('login-result');
            
            resultDiv.innerHTML = '<div class="loading">Probando login...</div>';
            
            try {
                const response = await fetch('/login/login.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });
                
                const responseText = await response.text();
                console.log('Response:', responseText);
                
                let data;
                try {
                    data = JSON.parse(responseText);
                } catch (e) {
                    throw new Error('Respuesta no es JSON válido: ' + responseText);
                }
                
                if (data.success) {
                    resultDiv.innerHTML = '<div class="success">✓ Login exitoso!</div><pre>' + 
                                        JSON.stringify(data, null, 2) + '</pre>';
                } else {
                    resultDiv.innerHTML = '<div class="error">✗ Login fallido: ' + 
                                        (data.message || 'Error desconocido') + '</div>';
                }
            } catch (error) {
                resultDiv.innerHTML = '<div class="error">Error de conexión: ' + error.message + '</div>';
                console.error('Error completo:', error);
            }
        });
        
        // Información del dispositivo
        const deviceInfo = {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            screenWidth: screen.width,
            screenHeight: screen.height,
            isMobile: /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent)
        };
        
        console.log('Device Info:', deviceInfo);
    </script>
</body>
</html>
