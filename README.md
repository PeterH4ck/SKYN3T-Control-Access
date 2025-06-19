# 🌐 SKYN3T Control System

![SKYN3T Logo](docs/images/logo-banner.png)

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/PeterH4ck/skyn3t-control-access)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4.svg)](https://php.net)
[![MariaDB](https://img.shields.io/badge/MariaDB-10.11%2B-003545.svg)](https://mariadb.org)

Sistema de Control y Monitoreo SKYN3T - Una solución integral para el control de dispositivos IoT con interfaz web moderna, gestión de usuarios y control de relé en tiempo real.

## 🚀 Características Principales

- **🔐 Sistema de Autenticación Robusto**
  - Roles jerárquicos (SuperUser, Admin, SupportAdmin, User)
  - Manejo de sesiones seguro
  - Protección contra ataques de fuerza bruta

- **🎛️ Control de Relé Multi-Interface**
  - Control web responsivo
  - Interfaz de pantalla táctil local
  - Botón físico de emergencia
  - API RESTful para integración

- **👥 Gestión Completa de Usuarios y Dispositivos**
  - CRUD completo de usuarios
  - Registro y monitoreo de dispositivos
  - Logs de actividad detallados

- **🎨 Interfaz Moderna con Glassmorphism**
  - Diseño responsivo mobile-first
  - Efectos visuales modernos
  - Tema oscuro optimizado

- **📊 Dashboard en Tiempo Real**
  - Estadísticas del sistema
  - Monitoreo de recursos
  - Estado de dispositivos en vivo

## 🖼️ Screenshots

<div align="center">
  <img src="docs/images/login-screen.png" width="45%" alt="Login Screen">
  <img src="docs/images/dashboard.png" width="45%" alt="Dashboard">
</div>

## 📋 Requisitos del Sistema

### Hardware
- Raspberry Pi 3/4 o superior
- Módulo relé compatible con GPIO
- (Opcional) Pantalla táctil para control local
- (Opcional) Botón físico para control manual

### Software
- Raspbian OS / Debian 12+
- Apache 2.4+
- PHP 7.4+ con extensiones:
  - PDO
  - PDO_MySQL
  - JSON
  - Session
- MariaDB 10.11+
- Python 3.8+ (para control GPIO)
- Git

## ⚡ Instalación Rápida

```bash
# Clonar el repositorio
git clone https://github.com/peterh4ck/skyn3t-control-access.git
cd skyn3t-control-system

# Ejecutar script de instalación
chmod +x scripts/install.sh
sudo ./scripts/install.sh

# Configurar variables de entorno
cp .env.example .env
nano .env

# Importar base de datos
mysql -u root -p < database/schema.sql
mysql -u root -p skyn3t_db < database/initial_data.sql
```

Para una guía detallada, consulta [INSTALL.md](INSTALL.md)

## 🔧 Configuración

### 1. Base de Datos
Edita las credenciales en `.env`:
```env
DB_HOST=localhost
DB_NAME=skyn3t_db
DB_USER=skyn3t_app
DB_PASS=admin
```

### 2. GPIO Pins
Configuración por defecto en `src/includes/config.php`:
```php
define('GPIO_RELAY_PIN', 23);   // Pin del relé
define('GPIO_LED_PIN', 16);     // Pin del LED
define('GPIO_BUTTON_PIN', 25);  // Pin del botón
```

### 3. Usuarios por Defecto
- **Admin**: `admin` / `admin`
- **SuperUser**: `peterh4ck` / `admin`

⚠️ **IMPORTANTE**: Cambia estas contraseñas inmediatamente después de la instalación.

## 📖 Documentación

- [📘 Guía de Instalación Completa](INSTALL.md)
- [📗 Documentación de APIs](docs/API.md)
- [📙 Estructura de Base de Datos](docs/DATABASE.md)
- [📕 Configuración de Hardware](docs/HARDWARE.md)
- [📔 Guía de Seguridad](docs/SECURITY.md)

## 🛠️ Desarrollo

### Estructura del Proyecto
```
src/
├── index.html          # Página principal
├── includes/           # Core PHP
├── api/               # Endpoints REST
├── login/             # Sistema de autenticación
├── dashboard/         # Panel de control
└── assets/            # Recursos estáticos
```

### Ejecutar en Modo Desarrollo
```bash
# Activar modo debug
sed -i "s/ENVIRONMENT=production/ENVIRONMENT=development/" .env

# Ver logs en tiempo real
tail -f /var/www/html/logs/*.log
```

### Contribuir
1. Fork el proyecto
2. Crea tu rama de característica (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add: Nueva característica'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 🧪 Testing

```bash
# Ejecutar tests de API
php tests/api/ApiTest.php

# Verificar conexión a base de datos
curl -X POST http://localhost/includes/database.php \
  -H "Content-Type: application/json" \
  -d '{"action":"test_connection"}'
```

## 📊 Estado del Proyecto

- [x] Sistema de autenticación
- [x] Dashboard principal
- [x] Control de relé básico
- [ ] APIs completas
- [ ] Gestión de dispositivos
- [ ] Sistema de notificaciones
- [ ] Programación de horarios
- [ ] Backup automático

## 🔒 Seguridad

Este proyecto implementa múltiples capas de seguridad:
- Autenticación basada en tokens
- Rate limiting para prevenir ataques
- Sanitización de todas las entradas
- Headers de seguridad HTTP
- Logs de auditoría completos

Para más detalles, consulta [SECURITY.md](docs/SECURITY.md)

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## 👥 Autores

- **PETERH4CK** - *Desarrollo inicial* - PeterH4ck(https://github.com/PeterH4ck)

## 🙏 Agradecimientos

- Comunidad Raspberry Pi
- Contribuidores del proyecto
- [Font Awesome](https://fontawesome.com) por los iconos

---

<p align="center">
  Hecho con ❤️ por SKYN3T - IT & NETWORK SOLUTIONS
</p>