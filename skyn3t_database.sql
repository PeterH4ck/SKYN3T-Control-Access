-- =============================================
-- SKYN3T - Sistema de Control y Monitoreo
-- Script de creación de base de datos
-- Versión: 2.0.0
-- Fecha: 2025-01-19
-- =============================================

-- Crear base de datos
CREATE DATABASE IF NOT EXISTS `skyn3t_db` 
DEFAULT CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE `skyn3t_db`;

-- =============================================
-- TABLA: users (usuarios del sistema)
-- =============================================
CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL UNIQUE,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) DEFAULT NULL,
  `full_name` varchar(100) DEFAULT NULL,
  `role` enum('SuperUser','Admin','SupportAdmin','User') NOT NULL DEFAULT 'User',
  `privileges` json DEFAULT NULL,
  `active` tinyint(1) DEFAULT 1,
  `phone` varchar(20) DEFAULT NULL,
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `last_login` datetime DEFAULT NULL,
  `login_count` int(11) DEFAULT 0,
  `failed_login_count` int(11) DEFAULT 0,
  `locked_until` datetime DEFAULT NULL,
  `created_by` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_username` (`username`),
  KEY `idx_role` (`role`),
  KEY `idx_active` (`active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: sessions (sesiones de usuarios)
-- =============================================
CREATE TABLE IF NOT EXISTS `sessions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `session_id` varchar(128) NOT NULL,
  `session_token` varchar(64) NOT NULL UNIQUE,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `last_activity` datetime DEFAULT CURRENT_TIMESTAMP,
  `is_active` tinyint(1) DEFAULT 1,
  `destroyed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_session_token` (`session_token`),
  KEY `idx_is_active` (`is_active`),
  CONSTRAINT `fk_sessions_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: access_log (registro de accesos)
-- =============================================
CREATE TABLE IF NOT EXISTS `access_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `action` varchar(50) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `details` json DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_action` (`action`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: devices (dispositivos del sistema)
-- =============================================
CREATE TABLE IF NOT EXISTS `devices` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `device_name` varchar(100) NOT NULL,
  `device_type` varchar(50) NOT NULL,
  `mac_address` varchar(17) NOT NULL UNIQUE,
  `ip_address` varchar(45) DEFAULT NULL,
  `status` enum('active','inactive') DEFAULT 'active',
  `location` varchar(100) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_device_type` (`device_type`),
  KEY `idx_status` (`status`),
  KEY `idx_created_by` (`created_by`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: relay_status (estado del relé)
-- =============================================
CREATE TABLE IF NOT EXISTS `relay_status` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `relay_state` tinyint(1) NOT NULL DEFAULT 0,
  `led_state` tinyint(1) NOT NULL DEFAULT 0,
  `changed_by` int(11) DEFAULT NULL,
  `change_method` enum('web','button','screen','schedule','api') DEFAULT 'web',
  `timestamp` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_timestamp` (`timestamp`),
  KEY `idx_changed_by` (`changed_by`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: notifications (notificaciones)
-- =============================================
CREATE TABLE IF NOT EXISTS `notifications` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(50) NOT NULL,
  `message` text NOT NULL,
  `data` json DEFAULT NULL,
  `target` varchar(100) DEFAULT NULL,
  `status` enum('unread','read') DEFAULT 'unread',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `read_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_type` (`type`),
  KEY `idx_status` (`status`),
  KEY `idx_target` (`target`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: php_sessions (sesiones PHP nativas)
-- =============================================
CREATE TABLE IF NOT EXISTS `php_sessions` (
  `id` varchar(128) NOT NULL,
  `data` text,
  `timestamp` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: audit_log (registro de auditoría)
-- =============================================
CREATE TABLE IF NOT EXISTS `audit_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `action` varchar(100) NOT NULL,
  `table_name` varchar(50) DEFAULT NULL,
  `record_id` int(11) DEFAULT NULL,
  `old_values` json DEFAULT NULL,
  `new_values` json DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_action` (`action`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: device_logs (logs de dispositivos)
-- =============================================
CREATE TABLE IF NOT EXISTS `device_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `device_id` int(11) NOT NULL,
  `action` varchar(50) NOT NULL,
  `details` json DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_device_id` (`device_id`),
  KEY `idx_created_at` (`created_at`),
  CONSTRAINT `fk_device_logs_device` FOREIGN KEY (`device_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: relay_control (control del relé)
-- =============================================
CREATE TABLE IF NOT EXISTS `relay_control` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `device_id` int(11) DEFAULT NULL,
  `action` enum('on','off','toggle') NOT NULL,
  `executed_by` int(11) DEFAULT NULL,
  `execution_time` datetime DEFAULT CURRENT_TIMESTAMP,
  `success` tinyint(1) DEFAULT 1,
  `error_message` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_device_id` (`device_id`),
  KEY `idx_executed_by` (`executed_by`),
  KEY `idx_execution_time` (`execution_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: relay_schedules (programación del relé)
-- =============================================
CREATE TABLE IF NOT EXISTS `relay_schedules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `device_id` int(11) DEFAULT NULL,
  `schedule_name` varchar(100) DEFAULT NULL,
  `start_time` time NOT NULL,
  `end_time` time NOT NULL,
  `days_of_week` json DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_by` int(11) DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_device_id` (`device_id`),
  KEY `idx_is_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: relay_states (estados del relé)
-- =============================================
CREATE TABLE IF NOT EXISTS `relay_states` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `device_id` int(11) DEFAULT NULL,
  `state` tinyint(1) NOT NULL DEFAULT 0,
  `voltage` decimal(5,2) DEFAULT NULL,
  `current` decimal(5,2) DEFAULT NULL,
  `power` decimal(7,2) DEFAULT NULL,
  `temperature` decimal(5,2) DEFAULT NULL,
  `recorded_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_device_id` (`device_id`),
  KEY `idx_recorded_at` (`recorded_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: system_config (configuración del sistema)
-- =============================================
CREATE TABLE IF NOT EXISTS `system_config` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `config_key` varchar(50) NOT NULL UNIQUE,
  `config_value` text DEFAULT NULL,
  `config_type` enum('string','integer','boolean','json') DEFAULT 'string',
  `description` text DEFAULT NULL,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_config_key` (`config_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: system_logs (logs del sistema)
-- =============================================
CREATE TABLE IF NOT EXISTS `system_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `level` enum('debug','info','warning','error','critical') NOT NULL,
  `message` text NOT NULL,
  `context` json DEFAULT NULL,
  `source` varchar(100) DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_level` (`level`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: system_settings (ajustes del sistema)
-- =============================================
CREATE TABLE IF NOT EXISTS `system_settings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `setting_group` varchar(50) DEFAULT NULL,
  `setting_key` varchar(50) NOT NULL UNIQUE,
  `setting_value` text DEFAULT NULL,
  `setting_type` varchar(20) DEFAULT 'string',
  `description` text DEFAULT NULL,
  `updated_by` int(11) DEFAULT NULL,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_setting_group` (`setting_group`),
  KEY `idx_setting_key` (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: residentes (información de residentes)
-- =============================================
CREATE TABLE IF NOT EXISTS `residentes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nombre` varchar(100) NOT NULL,
  `apellido` varchar(100) NOT NULL,
  `rut` varchar(12) NOT NULL UNIQUE,
  `telefono` varchar(20) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `direccion` varchar(200) DEFAULT NULL,
  `unidad` varchar(50) DEFAULT NULL,
  `estado` enum('activo','inactivo','suspendido') DEFAULT 'activo',
  `fecha_ingreso` date DEFAULT NULL,
  `fecha_salida` date DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_rut` (`rut`),
  KEY `idx_estado` (`estado`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: contactos_emergencia
-- =============================================
CREATE TABLE IF NOT EXISTS `contactos_emergencia` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `residente_id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `telefono` varchar(20) NOT NULL,
  `relacion` varchar(50) DEFAULT NULL,
  `prioridad` int(11) DEFAULT 1,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_residente_id` (`residente_id`),
  CONSTRAINT `fk_contactos_residente` FOREIGN KEY (`residente_id`) REFERENCES `residentes` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: vehiculos_residentes
-- =============================================
CREATE TABLE IF NOT EXISTS `vehiculos_residentes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `residente_id` int(11) NOT NULL,
  `patente` varchar(10) NOT NULL UNIQUE,
  `marca` varchar(50) DEFAULT NULL,
  `modelo` varchar(50) DEFAULT NULL,
  `color` varchar(30) DEFAULT NULL,
  `tipo` enum('automovil','motocicleta','camioneta','otro') DEFAULT 'automovil',
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_residente_id` (`residente_id`),
  KEY `idx_patente` (`patente`),
  CONSTRAINT `fk_vehiculos_residente` FOREIGN KEY (`residente_id`) REFERENCES `residentes` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: historial_residentes
-- =============================================
CREATE TABLE IF NOT EXISTS `historial_residentes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `residente_id` int(11) NOT NULL,
  `accion` varchar(100) NOT NULL,
  `descripcion` text DEFAULT NULL,
  `realizado_por` int(11) DEFAULT NULL,
  `fecha` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_residente_id` (`residente_id`),
  KEY `idx_fecha` (`fecha`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: solicitudes_residentes
-- =============================================
CREATE TABLE IF NOT EXISTS `solicitudes_residentes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `residente_id` int(11) NOT NULL,
  `tipo_solicitud` varchar(50) NOT NULL,
  `descripcion` text NOT NULL,
  `estado` enum('pendiente','en_proceso','completado','rechazado') DEFAULT 'pendiente',
  `prioridad` enum('baja','media','alta','urgente') DEFAULT 'media',
  `fecha_solicitud` datetime DEFAULT CURRENT_TIMESTAMP,
  `fecha_resolucion` datetime DEFAULT NULL,
  `resuelto_por` int(11) DEFAULT NULL,
  `comentarios` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_residente_id` (`residente_id`),
  KEY `idx_estado` (`estado`),
  KEY `idx_fecha_solicitud` (`fecha_solicitud`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: devices_deleted (dispositivos eliminados)
-- =============================================
CREATE TABLE IF NOT EXISTS `devices_deleted` (
  `id` int(11) NOT NULL,
  `device_name` varchar(100) NOT NULL,
  `device_type` varchar(50) NOT NULL,
  `mac_address` varchar(17) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `status` varchar(20) DEFAULT NULL,
  `location` varchar(100) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `deleted_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `deleted_by` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_deleted_at` (`deleted_at`),
  KEY `idx_deleted_by` (`deleted_by`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLA: usuarios (tabla legacy - mantener por compatibilidad)
-- =============================================
CREATE TABLE IF NOT EXISTS `usuarios` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) DEFAULT NULL,
  `role` varchar(20) DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- VISTA: vista_estadisticas_residentes
-- =============================================
CREATE OR REPLACE VIEW `vista_estadisticas_residentes` AS
SELECT 
    r.id,
    r.nombre,
    r.apellido,
    r.unidad,
    r.estado,
    COUNT(DISTINCT v.id) as total_vehiculos,
    COUNT(DISTINCT c.id) as total_contactos,
    COUNT(DISTINCT s.id) as total_solicitudes,
    SUM(CASE WHEN s.estado = 'pendiente' THEN 1 ELSE 0 END) as solicitudes_pendientes
FROM residentes r
LEFT JOIN vehiculos_residentes v ON r.id = v.residente_id AND v.estado = 'activo'
LEFT JOIN contactos_emergencia c ON r.id = c.residente_id
LEFT JOIN solicitudes_residentes s ON r.id = s.residente_id
GROUP BY r.id;

-- =============================================
-- INSERTAR DATOS INICIALES
-- =============================================

-- Insertar usuarios del sistema
-- Contraseña para ambos usuarios: admin
-- Hash generado con password_hash('admin', PASSWORD_BCRYPT)
INSERT INTO `users` (`username`, `password`, `email`, `full_name`, `role`, `privileges`, `active`, `created_at`) VALUES
('admin', '$2y$10$sBKLeph9XbawLauDPrxms.OdRsNwpQE/rkVsEVRA9Wa32L86CwJ06', 'admin@skyn3t.local', 'Administrador', 'Admin', '{"dashboard": true, "devices": true, "users": true, "relay": true, "logs": true}', 1, '2025-06-19 00:05:33'),
('peterh4ck', '$2y$10$sBKLeph9XbawLauDPrxms.OdRsNwpQE/rkVsEVRA9Wa32L86CwJ06', 'peterh4ck@skyn3t.local', 'Peter Hack', 'SuperUser', '{"all": true, "dashboard": true, "devices": true, "users": true, "relay": true, "logs": true, "system": true}', 1, '2025-06-19 00:05:45');

-- Insertar estado inicial del relé
INSERT INTO `relay_status` (`relay_state`, `led_state`, `changed_by`, `change_method`, `timestamp`) VALUES
(0, 0, 1, 'web', '2025-06-19 00:05:54');

-- Insertar dispositivo principal
INSERT INTO `devices` (`device_name`, `device_type`, `mac_address`, `ip_address`, `status`, `location`, `description`, `created_at`, `updated_at`, `created_by`) VALUES
('Relé Principal', 'Relay Controller', '00:11:22:33:44:55', '192.168.4.1', 'active', 'Sala Principal', 'Relé de control principal del sistema', '2025-06-19 00:06:07', '2025-06-19 00:06:07', 1);

-- Insertar configuración inicial del sistema
INSERT INTO `system_config` (`config_key`, `config_value`, `config_type`, `description`) VALUES
('system_name', 'SKYN3T', 'string', 'Nombre del sistema'),
('system_version', '2.0.0', 'string', 'Versión del sistema'),
('gpio_relay_pin', '23', 'integer', 'Pin GPIO para el relé'),
('gpio_led_pin', '16', 'integer', 'Pin GPIO para el LED'),
('gpio_button_pin', '25', 'integer', 'Pin GPIO para el botón'),
('session_lifetime', '1440', 'integer', 'Duración de sesión en minutos'),
('max_login_attempts', '5', 'integer', 'Intentos máximos de login'),
('lockout_time', '900', 'integer', 'Tiempo de bloqueo en segundos');

-- Insertar configuración de ajustes del sistema
INSERT INTO `system_settings` (`setting_group`, `setting_key`, `setting_value`, `setting_type`, `description`) VALUES
('general', 'timezone', 'America/Santiago', 'string', 'Zona horaria del sistema'),
('general', 'date_format', 'Y-m-d H:i:s', 'string', 'Formato de fecha'),
('general', 'language', 'es', 'string', 'Idioma del sistema'),
('security', 'password_min_length', '8', 'integer', 'Longitud mínima de contraseña'),
('security', 'enable_2fa', '0', 'boolean', 'Habilitar autenticación de dos factores'),
('relay', 'default_state', '0', 'boolean', 'Estado por defecto del relé'),
('relay', 'pulse_duration', '1000', 'integer', 'Duración del pulso en milisegundos');

-- Insertar usuarios legacy para compatibilidad
INSERT INTO `usuarios` (`username`, `password`, `email`, `role`) VALUES
('admin', '$2y$10$sBKLeph9XbawLauDPrxms.OdRsNwpQE/rkVsEVRA9Wa32L86CwJ06', 'admin@skyn3t.local', 'admin'),
('peterh4ck', '$2y$10$sBKLeph9XbawLauDPrxms.OdRsNwpQE/rkVsEVRA9Wa32L86CwJ06', 'peterh4ck@skyn3t.local', 'superuser'),
('guest', '$2y$10$sBKLeph9XbawLauDPrxms.OdRsNwpQE/rkVsEVRA9Wa32L86CwJ06', 'guest@skyn3t.local', 'user');

-- =============================================
-- PERMISOS DE USUARIO PARA LA BASE DE DATOS
-- =============================================

-- Crear usuario de aplicación si no existe
CREATE USER IF NOT EXISTS 'skyn3t_app'@'localhost' IDENTIFIED BY 'Skyn3t2025!';

-- Otorgar permisos completos sobre la base de datos
GRANT ALL PRIVILEGES ON `skyn3t_db`.* TO 'skyn3t_app'@'localhost';

-- Aplicar cambios de permisos
FLUSH PRIVILEGES;

-- =============================================
-- VERIFICACIÓN FINAL
-- =============================================
SELECT 'Base de datos SKYN3T creada exitosamente!' as mensaje;
SELECT COUNT(*) as tablas_creadas FROM information_schema.tables WHERE table_schema = 'skyn3t_db';
SELECT 'Usuarios admin y peterh4ck creados con contraseña: admin' as nota_importante;
