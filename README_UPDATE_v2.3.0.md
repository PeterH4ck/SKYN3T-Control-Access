# 🔐 SKYN3T Control Access System v2.3.0

Sistema de Control y Monitoreo IoT con gestión de usuarios por roles, control de dispositivos y dashboard administrativo.

![Version](https://img.shields.io/badge/version-2.3.0-blue.svg)
![Status](https://img.shields.io/badge/status-active%20development-green.svg)
![PHP](https://img.shields.io/badge/PHP-8.2+-purple.svg)
![MariaDB](https://img.shields.io/badge/MariaDB-10.11+-orange.svg)

---

## 📋 Tabla de Contenidos

- [Características](#-características)
- [Estado Actual](#-estado-actual)
- [Instalación Rápida](#-instalación-rápida)
- [Diagnóstico del Sistema](#-diagnóstico-del-sistema)
- [Uso del Sistema](#-uso-del-sistema)
- [Arquitectura](#-arquitectura)
- [APIs Disponibles](#-apis-disponibles)
- [Solución de Problemas](#-solución-de-problemas)
- [Contribuir](#-contribuir)

---

## ✨ Características

### **Implementadas en v2.3.0** ✅
- 🔐 **Autenticación robusta** con roles jerárquicos
- 🎯 **Redirección inteligente** según perfil de usuario
- 📊 **Dashboard administrativo** con interfaz moderna
- 👤 **Panel de usuario básico** para solicitudes
- 🔌 **APIs RESTful** parcialmente implementadas
- 🛡️ **Seguridad multicapa** con validación completa
- 📱 **Diseño responsive** mobile-first
- 🎨 **Efectos glassmorphism** en toda la interfaz

### **En Desarrollo** 🚧
- 🔧 Control GPIO físico
- 📈 Gráficos en tiempo real
- 🔔 Sistema de notificaciones
- 👥 Gestión completa de usuarios

---

## 📊 Estado Actual

### **Módulos Completados**

| Módulo | Estado | Progreso |
|--------|--------|----------|
| Sistema de Login | ✅ Completo | 100% |
| Dashboard Admin | ✅ Completo | 100% |
| Panel Usuario | ✅ Completo | 100% |
| APIs Core | ⚠️ Parcial | 40% |
| Control GPIO | ❌ Pendiente | 0% |

### **Usuarios del Sistema**

```bash
# Administrador
Usuario: admin
Password: admin
Rol: Admin

# Super Usuario  
Usuario: peterh4ck
Password: admin
Rol: SuperUser

# Usuario básico (opcional)
Usuario: usuario1
Password: admin
Rol: User
```

---

## 🚀 Instalación Rápida

### **Requisitos Previos**
- Raspberry Pi 3/4 con Raspbian/Debian 12
- Apache 2.4+
- PHP 8.2+
- MariaDB 10.11+
- Git

### **Instalación**

```bash
# 1. Clonar repositorio
git clone https://github.com/PeterH4ck/SKYN3T-Control-Access.git
cd SKYN3T-Control-Access

# 2. Copiar archivos al servidor web
sudo cp -r src/* /var/www/html/

# 3. Importar base de datos
mysql -u root -p < database/skyn3t_db.sql

# 4. Configurar permisos
sudo chown -R www-data:www-data /var/www/html/
sudo chmod -R 755 /var/www/html/

# 5. Reiniciar servicios
sudo systemctl restart apache2
sudo systemctl restart mariadb
```

---

## 🔍 Diagnóstico del Sistema

### **IMPORTANTE: Verificar Estado del Sistema**

**Opción 1 - Navegador Web:**
```
http://192.168.4.1/diagnostics/
```

**Opción 2 - Terminal/cURL:**
```bash
curl -X POST http://192.168.4.1/diagnostics/index.php \
  -d "action=run_diagnostics"
```

Este comando verificará:
- ✅ Conexión a base de datos
- ✅ Estructura de tablas
- ✅ Archivos del sistema
- ✅ Permisos de directorios
- ✅ Configuración PHP
- ✅ Estado de sesiones

---

## 📱 Uso del Sistema

### **1. Acceso al Sistema**

**URL de Login:**
```
http://192.168.4.1/login/index_login.html
```

### **2. Flujo por Rol de Usuario**

#### **Administradores (Admin/SuperUser)**
1. Login → Redirección automática a Dashboard
2. URL: `http://192.168.4.1/dashboard/dashboard.html`
3. Acceso completo a:
   - Control de dispositivos
   - Estadísticas del sistema
   - Gestión de usuarios
   - Configuración

#### **Usuarios Básicos (User)**
1. Login → Redirección a Panel de Usuario
2. URL: `http://192.168.4.1/input_data/input.html`
3. Acceso limitado a:
   - Formulario de solicitudes
   - Control básico de relé
   - Estado del sistema

### **3. Control de Relé**

Todos los usuarios pueden acceder al panel básico:
```
http://192.168.4.1/rele/index_rele.html
```

---

## 🏗️ Arquitectura

### **Estructura de Directorios**

```
/var/www/html/
├── login/              # Sistema de autenticación
├── dashboard/          # Panel administrativo
├── input_data/         # Panel de usuarios básicos
├── api/                # Endpoints RESTful
├── includes/           # Core del sistema
├── rele/              # Control de relé
└── diagnostics/       # Herramientas de diagnóstico
```

### **Stack Tecnológico**

- **Frontend**: HTML5, CSS3 (Glassmorphism), JavaScript ES6+
- **Backend**: PHP 8.2
- **Base de Datos**: MariaDB 10.11
- **Servidor**: Apache 2.4
- **Hardware**: Raspberry Pi GPIO

---

## 🔌 APIs Disponibles

### **Documentación Interactiva**
```
http://192.168.4.1/api/
```

### **Endpoints Implementados**

#### **1. Estado del Relé**
```bash
GET /api/relay/status.php
Authorization: Bearer YOUR_TOKEN
```

#### **2. Control del Relé**
```bash
POST /api/relay/control.php
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json

{
  "action": "toggle",
  "source": "api"
}
```

#### **3. Listar Dispositivos**
```bash
GET /api/devices/list.php?status=active&limit=10
Authorization: Bearer YOUR_TOKEN
```

#### **4. Agregar Dispositivo**
```bash
POST /api/devices/add.php
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json

{
  "name": "Nuevo Relé",
  "type": "relay",
  "location": "Sala Principal"
}
```

---

## 🔧 Solución de Problemas

### **Error: "Acceso Denegado" en Dashboard**

**Causa**: Usuario sin permisos administrativos  
**Solución**: Verificar rol en base de datos
```sql
SELECT username, role FROM users WHERE username = 'tu_usuario';
```

### **Error: "Database connection error"**

**Causa**: Credenciales incorrectas  
**Solución**: Verificar configuración en `/includes/config.php`
```php
define('DB_HOST', 'localhost');
define('DB_NAME', 'skyn3t_db');
define('DB_USER', 'skyn3t_app');
define('DB_PASS', 'Skyn3t2025!');
```

### **Dashboard no carga correctamente**

**Solución**: Ejecutar diagnóstico
```bash
curl -X POST http://192.168.4.1/diagnostics/index.php \
  -d "action=run_diagnostics"
```

### **Sesión expira rápidamente**

**Solución**: Ajustar tiempo de sesión en `config.php`
```php
define('SESSION_LIFETIME', 3600); // 1 hora
```

---

## 👥 Contribuir

### **Cómo Contribuir**

1. Fork el proyecto
2. Crea tu rama de características (`git checkout -b feature/NuevaCaracteristica`)
3. Commit tus cambios (`git commit -m 'Add: Nueva característica'`)
4. Push a la rama (`git push origin feature/NuevaCaracteristica`)
5. Abre un Pull Request

### **Guías de Estilo**

- **PHP**: Seguir PSR-12
- **JavaScript**: ES6+ con JSDoc
- **CSS**: Metodología BEM
- **Commits**: Formato convencional (feat:, fix:, docs:, etc.)

### **Testing**

Antes de enviar PR, ejecutar:
```bash
# Test de login
./tests/test_login.sh

# Test de APIs
./tests/test_apis.sh

# Diagnóstico completo
curl -X POST http://192.168.4.1/diagnostics/index.php \
  -d "action=run_diagnostics"
```

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver archivo [LICENSE](LICENSE) para más detalles.

---

## 🙏 Agradecimientos

- Comunidad Raspberry Pi
- Contribuidores del proyecto
- Equipo de desarrollo SKYN3T

---

## 📞 Contacto

**Proyecto**: SKYN3T Control Access  
**Versión**: 2.3.0  
**Autor**: PeterH4ck  
**GitHub**: [https://github.com/PeterH4ck/SKYN3T-Control-Access](https://github.com/PeterH4ck/SKYN3T-Control-Access)

---

**© 2025 SKYN3T - IT & NETWORK SOLUTIONS**