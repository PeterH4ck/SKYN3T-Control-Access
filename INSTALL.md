# 📘 GUÍA DE INSTALACIÓN - SKYN3T Control System

## 📋 Tabla de Contenidos
1. [Requisitos Previos](#requisitos-previos)
2. [Instalación del Sistema Base](#instalación-del-sistema-base)
3. [Configuración de Base de Datos](#configuración-de-base-de-datos)
4. [Configuración del Servidor Web](#configuración-del-servidor-web)
5. [Instalación del Proyecto](#instalación-del-proyecto)
6. [Configuración de Hardware](#configuración-de-hardware)
7. [Configuración de Seguridad](#configuración-de-seguridad)
8. [Verificación de la Instalación](#verificación-de-la-instalación)
9. [Solución de Problemas](#solución-de-problemas)

---

## 🔧 Requisitos Previos

### Sistema Operativo
- Raspbian OS Bullseye o superior
- Debian 11+ (alternativa)
- Ubuntu Server 20.04+ (alternativa)

### Hardware Mínimo
- Raspberry Pi 3B+ o superior
- 2GB RAM mínimo (4GB recomendado)
- 16GB tarjeta SD (32GB recomendado)
- Conexión a Internet estable

### Software Requerido
```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar paquetes esenciales
sudo apt install -y \
    apache2 \
    mariadb-server \
    php7.4 \
    php7.4-mysql \
    php7.4-curl \
    php7.4-json \
    php7.4-mbstring \
    php7.4-xml \
    git \
    python3 \
    python3-pip \
    python3-gpiozero
```

---

## 🚀 Instalación del Sistema Base

### 1. Actualizar el Sistema
```bash
sudo apt update
sudo apt upgrade -y
sudo apt autoremove -y
```

### 2. Configurar Timezone
```bash
sudo timedatectl set-timezone America/Santiago
```

### 3. Configurar Hostname
```bash
sudo hostnamectl set-hostname skyn3t-controller
echo "127.0.0.1 skyn3t-controller" | sudo tee -a /etc/hosts
```

---

## 🗄️ Configuración de Base de Datos

### 1. Asegurar MariaDB
```bash
sudo mysql_secure_installation
```
Responder:
- Enter current password: (presionar Enter)
- Set root password? Y
- New password: (crear contraseña segura)
- Remove anonymous users? Y
- Disallow root login remotely? Y
- Remove test database? Y
- Reload privilege tables? Y

### 2. Crear Base de Datos y Usuario
```bash
sudo mysql -u root -p
```

```sql
-- Crear base de datos
CREATE DATABASE skyn3t_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Crear usuario de aplicación
CREATE USER 'skyn3t_app'@'localhost' IDENTIFIED BY 'admin';

-- Otorgar permisos
GRANT ALL PRIVILEGES ON skyn3t_db.* TO 'skyn3t_app'@'localhost';
FLUSH PRIVILEGES;

-- Salir
EXIT;
```

### 3. Importar Estructura de Base de Datos
```bash
cd /path/to/skyn3t-control-system
mysql -u root -p skyn3t_db < database/schema.sql
mysql -u root -p skyn3t_db < database/initial_data.sql
```

---

## 🌐 Configuración del Servidor Web

### 1. Configurar Apache
```bash
# Habilitar módulos necesarios
sudo a2enmod rewrite
sudo a2enmod headers
sudo a2enmod ssl

# Crear configuración del sitio
sudo nano /etc/apache2/sites-available/skyn3t.conf
```

Contenido de `skyn3t.conf`:
```apache
<VirtualHost *:80>
    ServerName skyn3t.local
    DocumentRoot /var/www/html
    
    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog ${APACHE_LOG_DIR}/skyn3t-error.log
    CustomLog ${APACHE_LOG_DIR}/skyn3t-access.log combined
    
    # Headers de seguridad
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
</VirtualHost>
```

### 2. Activar el Sitio
```bash
# Desactivar sitio por defecto
sudo a2dissite 000-default.conf

# Activar sitio SKYN3T
sudo a2ensite skyn3t.conf

# Reiniciar Apache
sudo systemctl restart apache2
```

### 3. Configurar PHP
```bash
sudo nano /etc/php/7.4/apache2/php.ini
```

Ajustar estos valores:
```ini
max_execution_time = 300
memory_limit = 256M
post_max_size = 50M
upload_max_filesize = 50M
date.timezone = America/Santiago
```

---

## 📦 Instalación del Proyecto

### 1. Clonar el Repositorio
```bash
# Eliminar contenido anterior
sudo rm -rf /var/www/html/*

# Clonar proyecto
cd /var/www
sudo git clone https://github.com/PeterH4ck/skyn3t-control-system.git html

# Ajustar permisos
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html
```

### 2. Configurar Variables de Entorno
```bash
cd /var/www/html
sudo cp .env.example .env
sudo nano .env
```

Editar valores:
```env
# Entorno
ENVIRONMENT=production

# Base de datos
DB_HOST=localhost
DB_NAME=skyn3t_db
DB_USER=skyn3t_app
DB_PASS=admin

# Seguridad
ENCRYPTION_KEY=genera_una_clave_segura_de_32_caracteres

# GPIO
GPIO_RELAY_PIN=23
GPIO_LED_PIN=16
GPIO_BUTTON_PIN=25
```

### 3. Crear Directorios Necesarios
```bash
# Crear directorio de logs
sudo mkdir -p /var/www/html/logs
sudo chown www-data:www-data /var/www/html/logs
sudo chmod 755 /var/www/html/logs

# Crear directorio temporal
sudo mkdir -p /var/www/html/tmp
sudo chown www-data:www-data /var/www/html/tmp
sudo chmod 755 /var/www/html/tmp
```

---

## 🔌 Configuración de Hardware

### 1. Habilitar GPIO
```bash
# Agregar usuario www-data al grupo gpio
sudo usermod -a -G gpio www-data

# Instalar herramientas GPIO
sudo apt install -y python3-rpi.gpio
sudo pip3 install gpiozero
```

### 2. Configurar Permisos GPIO
```bash
sudo nano /etc/udev/rules.d/99-gpio.rules
```

Agregar:
```
SUBSYSTEM=="gpio", KERNEL=="gpiochip*", MODE="0666"
SUBSYSTEM=="gpio", KERNEL=="gpio*", MODE="0666"
```

### 3. Probar GPIO
```bash
# Test rápido del relé
gpio -g mode 23 out
gpio -g write 23 1  # Encender
sleep 2
gpio -g write 23 0  # Apagar
```

---

## 🔒 Configuración de Seguridad

### 1. Configurar Firewall
```bash
# Instalar UFW
sudo apt install -y ufw

# Configurar reglas
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS (futuro)

# Activar firewall
sudo ufw --force enable
```

### 2. Configurar Fail2ban
```bash
# Instalar
sudo apt install -y fail2ban

# Crear configuración local
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local
```

### 3. Cambiar Contraseñas por Defecto
```bash
# Acceder a la aplicación web
# Usuario: admin / Contraseña: admin
# CAMBIAR INMEDIATAMENTE después del primer login
```

---

## ✅ Verificación de la Instalación

### 1. Verificar Servicios
```bash
# Apache
sudo systemctl status apache2

# MariaDB
sudo systemctl status mariadb

# Ver logs
sudo tail -f /var/log/apache2/skyn3t-error.log
```

### 2. Test de Conexión a Base de Datos
```bash
curl -X POST http://localhost/includes/database.php \
  -H "Content-Type: application/json" \
  -d '{"action":"test_connection"}'
```

Respuesta esperada:
```json
{
  "success": true,
  "database_info": {
    "version": "10.11.11-MariaDB-0+deb12u1",
    "database": "skyn3t_db",
    "connection_status": "connected",
    "tables_count": 23
  }
}
```

### 3. Acceder a la Interfaz Web
1. Abrir navegador
2. Navegar a: `http://192.168.4.1`
3. Debería aparecer la página de verificación del sistema

---

## 🔧 Solución de Problemas

### Error: "Cannot connect to database"
```bash
# Verificar que MariaDB esté corriendo
sudo systemctl status mariadb

# Verificar credenciales
mysql -u skyn3t_app -p -D skyn3t_db

# Ver logs
sudo tail -f /var/www/html/logs/error.log
```

### Error: "Permission denied"
```bash
# Reparar permisos
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html
sudo chmod -R 777 /var/www/html/logs
```

### GPIO no funciona
```bash
# Verificar grupos del usuario
groups www-data

# Debe incluir 'gpio', si no:
sudo usermod -a -G gpio www-data
sudo systemctl restart apache2
```

### Página en blanco
```bash
# Activar errores de PHP
sudo nano /etc/php/7.4/apache2/php.ini
# Cambiar: display_errors = On

# Ver logs de Apache
sudo tail -f /var/log/apache2/error.log
```

---

## 📚 Recursos Adicionales

- [Documentación de APIs](docs/API.md)
- [Estructura de Base de Datos](docs/DATABASE.md)
- [Configuración de Hardware](docs/HARDWARE.md)
- [Guía de Seguridad](docs/SECURITY.md)

---

## 🆘 Soporte

Si encuentras problemas durante la instalación:
1. Revisa los logs en `/var/www/html/logs/`
2. Consulta la sección de [Issues](https://github.com/PeterH4ck/skyn3t-control-access/issues)
3. Crea un nuevo issue con detalles del error

---

<p align="center">
  © 2025 SKYN3T - IT & NETWORK SOLUTIONS
</p>
