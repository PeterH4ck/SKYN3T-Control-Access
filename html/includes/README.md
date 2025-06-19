# SKYN3T - Sistema de Includes v2.0

Este directorio contiene todos los archivos centrales del sistema SKYN3T para manejo de base de datos, autenticación, configuraciones y funciones auxiliares.

## 📁 Estructura de Archivos

```
/var/www/html/includes/
├── init.php           # 🚀 Inicializador principal (USAR ESTE)
├── database.php       # 🗄️ Conexión y manejo de MariaDB
├── auth.php          # 🔐 Sistema de autenticación y sesiones
├── config.php        # ⚙️ Configuraciones del sistema
├── functions.php     # 🛠️ Funciones auxiliares
├── .htaccess         # 🔒 Protección del directorio
└── README.md         # 📖 Esta documentación
```

## 🚀 Uso Rápido

### Incluir en cualquier archivo PHP:
```php
<?php
// Una sola línea inicializa todo el sistema
require_once '/var/www/html/includes/init.php';

// Ahora tienes acceso a todas las funciones
$user = getCurrentUser();
$db = Database::getInstance();
?>
```

## 🔧 Componentes Principales

### 1. **init.php** - Inicializador Principal
- ✅ Punto de entrada único para todo el sistema
- ✅ Verifica requisitos del sistema
- ✅ Configura manejadores de errores
- ✅ Inicializa todos los componentes automáticamente

### 2. **database.php** - Sistema de Base de Datos
- ✅ Conexión singleton a MariaDB (skyn3t_db)
- ✅ Funciones simplificadas para consultas
- ✅ Manejo automático de reconexión
- ✅ Verificación de estructura de la DB

#### Ejemplos de uso:
```php
// Obtener conexión
$db = Database::getInstance();

// Consulta simple
$user = $db->fetchOne("SELECT * FROM usuarios WHERE username = ?", [$username]);

// Múltiples registros
$devices = $db->fetchAll("SELECT * FROM devices WHERE active = 1");

// Insertar datos
$db->prepare("INSERT INTO logs (message) VALUES (?)", ["Login exitoso"]);
```

### 3. **auth.php** - Sistema de Autenticación
- ✅ Login seguro con verificación de contraseñas
- ✅ Manejo de sesiones con tokens
- ✅ Control de intentos fallidos y bloqueos
- ✅ Verificación de permisos por roles

#### Ejemplos de uso:
```php
// Verificar si está autenticado
if (isAuthenticated()) {
    echo "Usuario autenticado";
}

// Requerir autenticación (redirige si no está logueado)
requireAuth();

// Verificar permisos específicos
if (hasPermission('admin')) {
    echo "Acceso permitido";
}

// Obtener usuario actual
$user = getCurrentUser();
echo "Hola " . $user['name'];
```

### 4. **config.php** - Configuraciones del Sistema
- ✅ Configuraciones centralizadas
- ✅ Definición de roles y permisos
- ✅ Rutas del sistema
- ✅ Mensajes estándar

#### Ejemplos de uso:
```php
// Obtener configuración
$systemName = getConfig('SYSTEM_NAME');

// Verificar rol válido
if (isValidRole('Admin')) {
    echo "Rol válido";
}

// Obtener información del sistema
$info = getSystemInfo();
print_r($info);
```

### 5. **functions.php** - Funciones Auxiliares
- ✅ Sanitización y validación de datos
- ✅ Respuestas JSON estandarizadas
- ✅ Sistema de logging
- ✅ Funciones de utilidades

#### Ejemplos de uso:
```php
// Sanitizar entrada
$cleanInput = sanitizeInput($_POST['username']);

// Enviar respuesta JSON
sendSuccessResponse(['message' => 'Operación exitosa']);

// Escribir log
writeLog('info', 'Usuario inició sesión', ['user_id' => 123]);

// Formatear fecha
echo formatDate('2025-01-01', 'd/m/Y');
```

## 🔐 Seguridad Implementada

### Protecciones Incluidas:
- ✅ Sanitización automática de entradas
- ✅ Protección contra SQL Injection (PDO Prepared Statements)
- ✅ Protección XSS en salidas
- ✅ Tokens CSRF para formularios
- ✅ Limitación de intentos de login
- ✅ Encriptación de contraseñas (Argon2ID)
- ✅ Headers de seguridad HTTP
- ✅ Protección del directorio con .htaccess

### Uso de Seguridad:
```php
// Generar token CSRF
$token = generateCSRFToken();

// Verificar token CSRF
if (verifyCSRFToken($_POST['csrf_token'])) {
    // Procesar formulario
}

// Hash de contraseña seguro
$hashedPassword = hashPassword($password);
```

## 📊 Base de Datos (skyn3t_db)

### Tablas Requeridas:
- `usuarios` - Información de usuarios
- `sessions` - Sesiones activas
- `devices` - Dispositivos del sistema
- `access_log` - Log de accesos
- `notifications` - Notificaciones
- `system_logs` - Logs del sistema

### Verificar Estructura:
```php
$db = Database::getInstance();
$status = $db->checkDatabaseStructure();
print_r($status);
```

## 🔄 Flujo de Autenticación

### 1. Login:
```php
require_once '/var/www/html/includes/init.php';

$auth = new Auth();
$result = $auth->login($username, $password);

if ($result['success']) {
    // Redirigir según rol
    header('Location: ' . $result['redirect_url']);
}
```

### 2. Verificación de Sesión:
```php
require_once '/var/www/html/includes/init.php';

$auth = new Auth();
$session = $auth->verifySession($token);

if ($session['valid']) {
    // Sesión válida
    $user = $session['user'];
} else {
    // Redirigir al login
    header('Location: /login/index_login.html');
}
```

### 3. Logout:
```php
require_once '/var/www/html/includes/init.php';

$auth = new Auth();
$auth->logout($token);

// Redirigir al login
header('Location: /login/index_login.html');
```

## 🛠️ Funciones de Respuesta API

### Respuestas Estandarizadas:
```php
// Éxito
sendSuccessResponse($data, 'Operación completada');

// Error
sendErrorResponse('Mensaje de error', 400, 'ERROR_CODE');

// JSON personalizado
sendJSONResponse(['custom' => 'data'], 200);
```

## 📝 Sistema de Logging

### Niveles de Log:
- `emergency` - Emergencias del sistema
- `alert` - Alertas críticas
- `critical` - Errores críticos
- `error` - Errores generales
- `warning` - Advertencias
- `notice` - Notificaciones
- `info` - Información general
- `debug` - Información de debug

### Escribir Logs:
```php
// Log simple
writeLog('info', 'Usuario inició sesión');

// Log con contexto
writeLog('error', 'Error en base de datos', [
    'query' => $sql,
    'error' => $e->getMessage()
]);
```

## 🚨 Manejo de Errores

### Configuración Automática:
- ✅ Manejador de errores personalizado
- ✅ Captura de errores fatales
- ✅ Logging automático de errores
- ✅ Modo debug para desarrollo

### Activar Modo Debug:
```php
// En desarrollo
define('DEBUG', true);
require_once '/var/www/html/includes/init.php';
```

## 📱 Roles y Permisos

### Roles Disponibles:
- **SuperUser** - Acceso completo al sistema
- **Admin** - Administración completa
- **SupportAdmin** - Soporte y mantenimiento
- **User** - Usuario básico

### URLs de Redirección:
- **User** → `/input_data.html`
- **Admin/SuperUser** → `/dashboard/index.php`

## 🔧 Mantenimiento

### Limpiar Cache:
```php
clearCache(); // Todo el cache
clearCache('key'); // Cache específico
```

### Limpiar Sesiones Expiradas:
```php
cleanupExpiredSessions();
```

### Verificar Estado del Sistema:
```php
$status = getSystemStatus();
$health = verifySystemHealth();
```

## 📁 Directorios Automáticos

El sistema crea automáticamente:
- `/var/www/html/logs/` - Logs del sistema
- `/var/www/html/cache/` - Cache temporal
- `/var/www/html/uploads/` - Archivos subidos

## 🚀 Implementación en Páginas

### Página Básica:
```php
<?php
require_once '/var/www/html/includes/init.php';
requireAuth(); // Requiere estar logueado
?>
<!DOCTYPE html>
<html>
<head>
    <title><?= SystemConfig::SYSTEM_NAME ?></title>
</head>
<body>
    <h1>Bienvenido <?= getCurrentUser()['name'] ?></h1>
</body>
</html>
```

### API Endpoint:
```php
<?php
require_once '/var/www/html/includes/init.php';

// Verificar método
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendErrorResponse('Método no permitido', 405);
}

// Verificar autenticación
if (!isAuthenticated()) {
    sendErrorResponse('No autorizado', 401);
}

// Procesar petición
$data = json_decode(file_get_contents('php://input'), true);
$input = sanitizeInput($data);

// Responder
sendSuccessResponse($result, 'Operación exitosa');
?>
```

## ⚠️ Notas Importantes

1. **Siempre usar `init.php`** - No incluir archivos individuales
2. **Verificar autenticación** - Usar `requireAuth()` en páginas protegidas
3. **Sanitizar entradas** - Usar `sanitizeInput()` para datos del usuario
4. **Usar respuestas JSON** - Para APIs usar `sendJSONResponse()`
5. **Logging** - Registrar eventos importantes con `writeLog()`

## 🆘 Solución de Problemas

### Error: "No se puede conectar a la base de datos"
- Verificar configuración en `database.php`
- Verificar que MariaDB esté ejecutándose
- Verificar credenciales de la DB

### Error: "Archivo no encontrado"
- Verificar rutas en includes
- Verificar permisos de archivos
- Verificar que todos los archivos estén presentes

### Error: "Acceso denegado"
- Verificar permisos de directorio
- Verificar configuración de `.htaccess`
- Verificar roles de usuario

---

**SKYN3T System v2.0** - Sistema completo y modular para control de acceso y dispositivos.