# CHANGELOG - SKYN3T Control System

## [2.3.0] - 2025-06-19

### 🎉 Added
- **Sistema de redirección por roles** completamente funcional
  - SuperUser/Admin → `/dashboard/dashboard.html`
  - User → `/input_data/input.html`
- **Dashboard administrativo** completo con:
  - Sidebar navegable
  - Control de dispositivos (simulado)
  - Estadísticas en tiempo real
  - Efectos glassmorphism
  - Responsive design
- **Panel de usuario básico** (`/input_data/input.html`)
  - Formulario de solicitudes
  - Accesos rápidos limitados
  - Verificación de permisos
- **APIs de dispositivos**:
  - `GET /api/devices/list.php` - Listar dispositivos con filtros
  - `POST /api/devices/add.php` - Agregar nuevos dispositivos
- **Sistema de verificación de acceso**:
  - `check_dashboard_access.php` - Verificación de permisos por rol
  - Protección de rutas administrativas
- **API temporal de dispositivos** (`devices_api.php`)
  - Simulación de dispositivos para desarrollo
  - Estadísticas mock para testing

### 🔧 Fixed
- **Conflicto `get_current_user()`**: Renombrada a `get_authenticated_user()` para evitar conflicto con función nativa PHP
- **Conflicto `session_unset()`**: Renombrada a `session_remove()` 
- **Error `Database::fetch()`**: Corregido uso incorrecto de método PDO
- **Inconsistencias de base de datos**:
  - `is_active` → `active` en tabla `users`
  - `created_at` → `timestamp` en tabla `access_log`
- **Redirección de login**: Ahora respeta roles de usuario correctamente
- **Referencias a `SystemConfig`**: Eliminadas referencias a clase inexistente

### 🔄 Changed
- **Login mejorado** (`login.php`):
  - Validación de roles mejorada
  - Redirección dinámica según rol
  - Mejor manejo de errores
  - Logging de intentos mejorado
- **Sistema de sesiones**:
  - Almacenamiento en base de datos
  - Regeneración automática de IDs
  - Detección de hijacking
- **Estructura de directorios**:
  - Dashboard movido a `/dashboard/`
  - Input data en `/input_data/`
  - Mejor organización modular

### 🏗️ Technical Details

#### Database Schema Updates
```sql
-- Usuarios activos
UPDATE users SET active = 1 WHERE username IN ('admin', 'peterh4ck');

-- Contraseñas actualizadas (hash para 'admin')
UPDATE users SET password = '$2y$10$8K1yW1D5F7Q3YBwSgMjUa.rFfV9mxwBNZBfLxKGqI4YbYk9VxeEKu';
```

#### New File Structure
```
/dashboard/
├── dashboard.html
├── check_dashboard_access.php
├── logout.php
└── devices_api.php

/input_data/
└── input.html
```

#### API Endpoints Status
- ✅ `/api/relay/status.php` - GET
- ✅ `/api/relay/control.php` - POST  
- ✅ `/api/devices/list.php` - GET
- ✅ `/api/devices/add.php` - POST
- ⏳ `/api/devices/update.php` - PUT (pending)
- ⏳ `/api/devices/delete.php` - DELETE (pending)

### 📊 Statistics
- **Files modified**: 15+
- **New files created**: 8
- **Lines of code added**: ~2,500
- **Test coverage**: Basic manual testing
- **Performance impact**: Minimal

### 🔒 Security Updates
- Added CSRF token validation in forms
- Implemented role-based access control (RBAC)
- Session hijacking protection
- Input sanitization in all new endpoints
- Prepared statements for all database queries

### 📝 Migration Notes

To update from v2.0.0 to v2.3.0:

1. **Update login.php**:
   ```bash
   sudo cp /path/to/new/login.php /var/www/html/login/
   ```

2. **Create new directories**:
   ```bash
   sudo mkdir -p /var/www/html/dashboard
   sudo mkdir -p /var/www/html/input_data
   ```

3. **Copy new files**:
   ```bash
   sudo cp dashboard/* /var/www/html/dashboard/
   sudo cp input_data/* /var/www/html/input_data/
   ```

4. **Set permissions**:
   ```bash
   sudo chown -R www-data:www-data /var/www/html/
   sudo chmod -R 755 /var/www/html/
   ```

5. **Update database** (if adding test user):
   ```sql
   INSERT INTO users (username, password, role, active, created_at) 
   VALUES ('usuario1', '$2y$10$8K1yW1D5F7Q3YBwSgMjUa.rFfV9mxwBNZBfLxKGqI4YbYk9VxeEKu', 'User', 1, NOW());
   ```

### 🐛 Known Issues
- Dashboard device selector needs real device integration
- Some API endpoints return mock data
- GPIO control not yet integrated
- WebSocket support pending for real-time updates

### 🔜 Next Release Preview (v2.4.0)
- Complete remaining API endpoints
- Real GPIO integration
- WebSocket implementation for real-time updates
- User management interface
- System settings panel

---

## [2.0.0] - 2025-06-19 (Previous)

### Added
- Initial system setup
- Basic authentication
- Database structure
- Core includes (config, database, auth, security, session)

---

## [1.0.0] - 2025-06-18 (Initial)

### Added
- Project initialization
- Basic file structure
- Initial database schema

---

**Note**: For detailed implementation status, run diagnostics:
```bash
curl -X POST http://192.168.4.1/diagnostics/index.php -d "action=run_diagnostics"
```