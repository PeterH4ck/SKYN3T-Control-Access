# 🔐 PLATAFORMA DE ADMINISTRACIÓN TOTAL SKYN3T v1.0

## Sistema de Gestión Completa de Usuarios y Permisos - **ACCESO EXCLUSIVO PETERH4CK**

---

## 📍 UBICACIÓN DEL SISTEMA
```
/var/www/html/sistema/admin_users/
```

## 🎯 DESCRIPCIÓN GENERAL

Plataforma de administración total del sistema SKYN3T diseñada **EXCLUSIVAMENTE** para el usuario `peterh4ck` con rol `SuperUser`. Proporciona control completo sobre:

- ✅ **Gestión Total de Usuarios y Roles**
- ✅ **Administración Completa de Base de Datos**  
- ✅ **Control de Permisos y Privilegios**
- ✅ **Monitoreo de Seguridad en Tiempo Real**
- ✅ **Herramientas de Mantenimiento del Sistema**
- ✅ **Ejecución Directa de SQL (¡PELIGROSO!)**
- ✅ **Backup y Restauración de BD**

## 🏗️ ESTRUCTURA DE ARCHIVOS

```
/var/www/html/sistema/admin_users/
├── index.html                    # Interfaz principal (COMPLETA)
├── check_admin_access.php        # Verificación de acceso exclusivo (COMPLETA)
├── admin_api.php                 # API de administración total (COMPLETA)
├── README_ADMIN.md              # Esta documentación
└── assets/                      # Recursos adicionales (opcional)
    ├── css/
    ├── js/ 
    └── images/
```

## 🔒 SEGURIDAD Y ACCESO

### **VERIFICACIÓN ESTRICTA DE ACCESO**

La plataforma implementa múltiples capas de seguridad:

```php
// Solo peterh4ck puede acceder
if ($username !== 'peterh4ck') {
    // ACCESO DENEGADO
}

// Debe tener rol SuperUser
if ($role !== 'SuperUser') {
    // PERMISOS INSUFICIENTES
}
```

### **LOGS DE SEGURIDAD**

Todos los intentos de acceso no autorizados son registrados:

```
UNAUTHORIZED ADMIN ACCESS ATTEMPT: {
    "user": "usuario_intruso",
    "role": "Admin", 
    "ip": "192.168.4.100",
    "time": "2025-06-19 16:00:00"
}
```

## 🚀 INSTALACIÓN Y CONFIGURACIÓN

### **PASO 1: Crear Directorio**
```bash
sudo mkdir -p /var/www/html/sistema/admin_users
sudo chown www-data:www-data /var/www/html/sistema/admin_users
sudo chmod 755 /var/www/html/sistema/admin_users
```

### **PASO 2: Desplegar Archivos**
```bash
# Copiar archivos del sistema de administración
sudo cp index.html /var/www/html/sistema/admin_users/
sudo cp check_admin_access.php /var/www/html/sistema/admin_users/
sudo cp admin_api.php /var/www/html/sistema/admin_users/

# Establecer permisos
sudo chown www-data:www-data /var/www/html/sistema/admin_users/*
sudo chmod 644 /var/www/html/sistema/admin_users/*.html
sudo chmod 644 /var/www/html/sistema/admin_users/*.php
```

### **PASO 3: Verificar Dependencias**

La plataforma requiere:
- ✅ PHP 7.4+ con PDO/MySQL
- ✅ MariaDB 10.11.11 (skyn3t_db)
- ✅ Apache con mod_rewrite
- ✅ Sistema de sesiones PHP funcional
- ✅ Usuario `peterh4ck` con rol `SuperUser` en BD

### **PASO 4: Verificar Base de Datos**

```sql
-- Verificar usuario peterh4ck
SELECT username, role, active, privileges 
FROM users 
WHERE username = 'peterh4ck';

-- Resultado esperado:
-- username: peterh4ck
-- role: SuperUser  
-- active: 1
-- privileges: {"all": true, "dashboard": true, ...}
```

## 🎛️ FUNCIONALIDADES PRINCIPALES

### **1. GESTIÓN DE USUARIOS**

#### **Estadísticas Rápidas**
- Total de usuarios en el sistema
- Usuarios activos vs inactivos
- Distribución por roles
- Sesiones activas en tiempo real

#### **Operaciones CRUD Completas**
```javascript
// Listar usuarios
GET /admin_api.php?action=list_users

// Obtener usuario específico  
GET /admin_api.php?action=get_user&id=123

// Crear usuario
POST /admin_api.php?action=create_user
{
    "username": "nuevo_usuario",
    "password": "password_segura",
    "role": "Admin",
    "active": true
}

// Actualizar usuario
PUT /admin_api.php?action=update_user&id=123
{
    "role": "SupportAdmin",
    "active": false
}

// Eliminar usuario  
DELETE /admin_api.php?action=delete_user&id=123
```

#### **Protecciones Especiales**
- ❌ **NO** se puede eliminar a `peterh4ck`
- ❌ **NO** se puede modificar desde otra cuenta
- ✅ **SÍ** se pueden gestionar todos los demás usuarios

### **2. ADMINISTRACIÓN DE BASE DE DATOS**

#### **Exploración de Estructura**
```javascript
// Listar todas las tablas
GET /admin_api.php?action=list_tables

// Ver estructura de tabla específica
GET /admin_api.php?action=table_structure&table=users
```

#### **Ejecución Directa de SQL** ⚠️ **¡PELIGROSO!**
```javascript
POST /admin_api.php?action=execute_sql
{
    "sql": "SELECT * FROM users WHERE role = 'Admin'"
}
```

**ADVERTENCIA**: Esta funcionalidad permite ejecutar **CUALQUIER** comando SQL. Úsala con extrema precaución.

### **3. MONITOREO DE SEGURIDAD**

#### **Sesiones Activas**
```javascript
GET /admin_api.php?action=active_sessions
```

#### **Información del Sistema**
```javascript
GET /admin_api.php?action=system_info
```

### **4. GESTIÓN DE ROLES Y PERMISOS**

#### **Roles Disponibles**
- **User**: Acceso básico (dashboard, relay)
- **SupportAdmin**: Soporte técnico (devices, logs)  
- **Admin**: Gestión general (users, devices, logs)
- **SuperUser**: Control total del sistema

#### **Permisos Granulares**
```json
{
    "dashboard": true,
    "devices": true, 
    "users": true,
    "relay": true,
    "logs": true,
    "system": true,
    "database_admin": true,
    "sql_execution": true
}
```

## 🎨 INTERFAZ DE USUARIO

### **Diseño Consistente**
- ✅ Logo SKYN3T centrado (`/images/logo.png`)
- ✅ Fondo con imagen de la tierra (`login-background.jpeg`)
- ✅ Efectos glassmorphism avanzados
- ✅ Botones flotantes (menú y logout)
- ✅ Sidebar responsivo con todos los enlaces
- ✅ Sin header fijo (siguiendo el patrón de `index_rele.html`)

### **Navegación del Sidebar**
```html
<!-- Enlaces principales -->
Dashboard → /dashboard/dashboard.html
Backups → /sistema/backup_interface.html
Control Principal → /rele/index_rele.html
Diagnóstico → http://192.168.4.1/diagnostics/
Dispositivos → /devices/index_devices.html
Estadísticas → En desarrollo
Residentes → /residentes/index.html
Usuarios → /sistema/admin_users/ (ACTUAL)

<!-- Configuración -->  
Mi Perfil → En desarrollo
Cerrar Sesión → Funcional
Ayuda → En desarrollo
```

### **Tabs del Sistema**
1. **👥 Gestión de Usuarios** - CRUD completo de usuarios
2. **🏷️ Roles y Permisos** - Administración de roles
3. **🗄️ Administración BD** - Control total de base de datos
4. **🔒 Seguridad** - Monitoreo y logs de seguridad
5. **⚙️ Sistema** - Configuración y mantenimiento

## 📊 ESTADÍSTICAS EN TIEMPO REAL

El dashboard muestra:

```javascript
{
    "total_users": 3,           // Total usuarios
    "active_users": 2,          // Usuarios activos  
    "admin_users": 2,           // Admins + SuperUsers
    "total_tables": 23,         // Tablas en BD
    "active_sessions": 1,       // Sesiones activas
    "total_residents": 0,       // Residentes (si aplicable)
    "active_devices": 1,        // Dispositivos activos
    "recent_logs": 99           // Logs últimas 24h
}
```

## 🛡️ CONSIDERACIONES DE SEGURIDAD

### **DO's ✅**
- ✅ Siempre verificar que eres `peterh4ck` antes de usar
- ✅ Mantener sesiones seguras (máximo 8 horas)
- ✅ Revisar logs de seguridad regularmente
- ✅ Hacer backup antes de cambios importantes
- ✅ Usar contraseñas seguras para nuevos usuarios

### **DON'Ts ❌**
- ❌ **NUNCA** compartir acceso a esta plataforma
- ❌ **NUNCA** ejecutar SQL sin estar seguro
- ❌ **NUNCA** eliminar usuarios críticos del sistema
- ❌ **NUNCA** modificar permisos de `peterh4ck`
- ❌ **NUNCA** dar acceso SuperUser a usuarios no confiables

## 🔧 DEBUGGING Y LOGS

### **Logs de Acceso**
```bash
# Ver logs de PHP
sudo tail -f /var/log/apache2/error.log

# Ver logs del sistema
sudo tail -f /var/www/html/logs/system.log
```

### **Debugging de Sesiones**
```javascript
// Verificar acceso
console.log('🔍 Verificando acceso de administración total...');

// En caso de problemas
console.error('❌ Error verificando acceso admin:', error);
```

## 🚨 CASOS DE EMERGENCIA

### **Bloqueo de Acceso**
Si `peterh4ck` queda bloqueado:

```sql
-- Reactivar cuenta desde MySQL
UPDATE users 
SET active = 1, login_attempts = 0, locked_until = NULL 
WHERE username = 'peterh4ck';

-- Verificar sesiones
SELECT * FROM sessions WHERE user_id = 2;
```

### **Restauración de Permisos**
```sql
-- Restaurar permisos completos
UPDATE users 
SET privileges = '{"all": true, "dashboard": true, "devices": true, "users": true, "relay": true, "logs": true, "system": true, "backups": true, "diagnostics": true, "residents": true, "statistics": true}'
WHERE username = 'peterh4ck';
```

## 📞 SOPORTE TÉCNICO

### **Información del Sistema**
- **Versión**: SKYN3T v3.0.1
- **Base de Datos**: MariaDB 10.11.11 (skyn3t_db)
- **Servidor**: Apache en 192.168.4.1:80
- **PHP**: 7.4+ con extensiones requeridas

### **Contacto**
Esta plataforma es **auto-gestionada** por `peterh4ck`. No hay soporte externo disponible.

---

## ⚠️ ADVERTENCIA FINAL

Esta plataforma otorga **CONTROL TOTAL** sobre el sistema SKYN3T. Su mal uso puede:

- 🔥 **Destruir toda la base de datos**
- 🔥 **Bloquear todos los usuarios** 
- 🔥 **Corromper el sistema completo**
- 🔥 **Comprometer la seguridad total**

**¡Úsala con EXTREMA responsabilidad!**

---

**© 2025 SKYN3T Systems - Plataforma de Administración Total**
**ACCESO EXCLUSIVO: peterh4ck**