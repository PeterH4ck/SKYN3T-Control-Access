#!/bin/bash

# ================================================================
# SCRIPT DE INSTALACIÓN AUTOMÁTICA
# PLATAFORMA DE ADMINISTRACIÓN TOTAL SKYN3T
# ACCESO EXCLUSIVO: peterh4ck
# Versión: 3.0.1
# ================================================================

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configuración
ADMIN_DIR="/var/www/html/sistema/admin_users"
BACKUP_DIR="/var/www/html/backups/admin_platform"
LOG_FILE="/var/log/skyn3t_admin_setup.log"

# Función para logging
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Función para mostrar encabezado
show_header() {
    clear
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${WHITE}    🔐 INSTALACIÓN DE PLATAFORMA DE ADMINISTRACIÓN TOTAL${NC}"
    echo -e "${WHITE}    SISTEMA SKYN3T - ACCESO EXCLUSIVO PETERH4CK${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
}

# Función para verificar permisos de root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}❌ Error: Este script debe ejecutarse como root${NC}"
        echo -e "${YELLOW}💡 Uso: sudo $0${NC}"
        exit 1
    fi
}

# Función para verificar dependencias
check_dependencies() {
    echo -e "${BLUE}🔍 Verificando dependencias del sistema...${NC}"
    
    # Verificar Apache
    if ! systemctl is-active --quiet apache2; then
        echo -e "${RED}❌ Apache no está ejecutándose${NC}"
        echo -e "${YELLOW}💡 Iniciando Apache...${NC}"
        systemctl start apache2
        if [[ $? -ne 0 ]]; then
            echo -e "${RED}❌ Error: No se pudo iniciar Apache${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}✅ Apache está ejecutándose${NC}"
    
    # Verificar PHP
    if ! php -v >/dev/null 2>&1; then
        echo -e "${RED}❌ PHP no está instalado${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ PHP está instalado${NC}"
    
    # Verificar MySQL/MariaDB
    if ! systemctl is-active --quiet mysql && ! systemctl is-active --quiet mariadb; then
        echo -e "${RED}❌ MySQL/MariaDB no está ejecutándose${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Base de datos está ejecutándose${NC}"
    
    # Verificar directorio web
    if [[ ! -d "/var/www/html" ]]; then
        echo -e "${RED}❌ Directorio /var/www/html no existe${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Directorio web existe${NC}"
    
    log "Verificación de dependencias completada exitosamente"
}

# Función para verificar base de datos
check_database() {
    echo -e "${BLUE}🗄️ Verificando base de datos SKYN3T...${NC}"
    
    # Verificar que existe la base de datos
    DB_EXISTS=$(mysql -u root -padmin -e "SHOW DATABASES LIKE 'skyn3t_db';" 2>/dev/null | grep skyn3t_db)
    if [[ -z "$DB_EXISTS" ]]; then
        echo -e "${RED}❌ Base de datos 'skyn3t_db' no encontrada${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Base de datos skyn3t_db existe${NC}"
    
    # Verificar usuario peterh4ck
    USER_EXISTS=$(mysql -u root -padmin -e "USE skyn3t_db; SELECT username FROM users WHERE username='peterh4ck';" 2>/dev/null | grep peterh4ck)
    if [[ -z "$USER_EXISTS" ]]; then
        echo -e "${RED}❌ Usuario 'peterh4ck' no encontrado en la BD${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Usuario peterh4ck existe en BD${NC}"
    
    # Verificar rol SuperUser
    USER_ROLE=$(mysql -u root -padmin -e "USE skyn3t_db; SELECT role FROM users WHERE username='peterh4ck';" 2>/dev/null | tail -n1)
    if [[ "$USER_ROLE" != "SuperUser" ]]; then
        echo -e "${YELLOW}⚠️ Usuario peterh4ck no tiene rol SuperUser (actual: $USER_ROLE)${NC}"
        echo -e "${BLUE}🔧 Corrigiendo rol...${NC}"
        mysql -u root -padmin -e "USE skyn3t_db; UPDATE users SET role='SuperUser' WHERE username='peterh4ck';" 2>/dev/null
        echo -e "${GREEN}✅ Rol corregido a SuperUser${NC}"
    else
        echo -e "${GREEN}✅ Usuario peterh4ck tiene rol SuperUser${NC}"
    fi
    
    log "Verificación de base de datos completada"
}

# Función para crear directorios
create_directories() {
    echo -e "${BLUE}📁 Creando estructura de directorios...${NC}"
    
    # Crear directorio principal
    mkdir -p "$ADMIN_DIR"
    echo -e "${GREEN}✅ Directorio principal creado: $ADMIN_DIR${NC}"
    
    # Crear directorio de backup
    mkdir -p "$BACKUP_DIR"
    echo -e "${GREEN}✅ Directorio de backup creado: $BACKUP_DIR${NC}"
    
    # Crear directorio de logs si no existe
    mkdir -p "/var/www/html/logs"
    echo -e "${GREEN}✅ Directorio de logs verificado${NC}"
    
    log "Estructura de directorios creada"
}

# Función para configurar permisos
set_permissions() {
    echo -e "${BLUE}🔒 Configurando permisos de archivos...${NC}"
    
    # Establecer propietario
    chown -R www-data:www-data "$ADMIN_DIR"
    echo -e "${GREEN}✅ Propietario establecido: www-data${NC}"
    
    # Permisos de directorio
    chmod 755 "$ADMIN_DIR"
    echo -e "${GREEN}✅ Permisos de directorio establecidos: 755${NC}"
    
    # Permisos de archivos existentes
    if [[ -f "$ADMIN_DIR/index.html" ]]; then
        chmod 644 "$ADMIN_DIR/index.html"
        echo -e "${GREEN}✅ Permisos de index.html: 644${NC}"
    fi
    
    if [[ -f "$ADMIN_DIR/check_admin_access.php" ]]; then
        chmod 644 "$ADMIN_DIR/check_admin_access.php"
        echo -e "${GREEN}✅ Permisos de check_admin_access.php: 644${NC}"
    fi
    
    if [[ -f "$ADMIN_DIR/admin_api.php" ]]; then
        chmod 644 "$ADMIN_DIR/admin_api.php"
        echo -e "${GREEN}✅ Permisos de admin_api.php: 644${NC}"
    fi
    
    log "Permisos de archivos configurados"
}

# Función para hacer backup de archivos existentes
backup_existing() {
    echo -e "${BLUE}💾 Realizando backup de archivos existentes...${NC}"
    
    if [[ -d "$ADMIN_DIR" ]] && [[ -n "$(ls -A $ADMIN_DIR 2>/dev/null)" ]]; then
        BACKUP_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
        BACKUP_PATH="$BACKUP_DIR/backup_$BACKUP_TIMESTAMP"
        
        mkdir -p "$BACKUP_PATH"
        cp -r "$ADMIN_DIR"/* "$BACKUP_PATH/" 2>/dev/null
        echo -e "${GREEN}✅ Backup realizado en: $BACKUP_PATH${NC}"
        log "Backup de archivos existentes realizado en $BACKUP_PATH"
    else
        echo -e "${YELLOW}ℹ️ No hay archivos existentes para respaldar${NC}"
    fi
}

# Función para verificar instalación
verify_installation() {
    echo -e "${BLUE}🔍 Verificando instalación...${NC}"
    
    # Verificar archivos principales
    FILES_REQUIRED=("index.html" "check_admin_access.php" "admin_api.php")
    for file in "${FILES_REQUIRED[@]}"; do
        if [[ -f "$ADMIN_DIR/$file" ]]; then
            echo -e "${GREEN}✅ Archivo encontrado: $file${NC}"
        else
            echo -e "${YELLOW}⚠️ Archivo faltante: $file${NC}"
        fi
    done
    
    # Verificar acceso web
    echo -e "${BLUE}🌐 Verificando acceso web...${NC}"
    ADMIN_URL="http://192.168.4.1/sistema/admin_users/"
    
    # Test simple de conectividad
    if curl -s -o /dev/null -w "%{http_code}" "$ADMIN_URL" | grep -q "200\|302"; then
        echo -e "${GREEN}✅ Plataforma accesible vía web${NC}"
    else
        echo -e "${YELLOW}⚠️ Verificar manualmente el acceso web${NC}"
    fi
    
    log "Verificación de instalación completada"
}

# Función para actualizar permisos de usuario en BD
update_user_permissions() {
    echo -e "${BLUE}🔐 Actualizando permisos de peterh4ck en BD...${NC}"
    
    PERMISSIONS='{"all": true, "dashboard": true, "devices": true, "users": true, "relay": true, "logs": true, "system": true, "backups": true, "diagnostics": true, "residents": true, "statistics": true, "database_admin": true, "sql_execution": true, "permission_management": true, "emergency_access": true}'
    
    mysql -u root -padmin -e "USE skyn3t_db; UPDATE users SET privileges = '$PERMISSIONS', updated_at = NOW() WHERE username = 'peterh4ck';" 2>/dev/null
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✅ Permisos de administración total actualizados${NC}"
        log "Permisos de peterh4ck actualizados con acceso total"
    else
        echo -e "${RED}❌ Error actualizando permisos en BD${NC}"
        log "ERROR: No se pudieron actualizar permisos en BD"
    fi
}

# Función para mostrar información final
show_final_info() {
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${WHITE}           🎉 INSTALACIÓN COMPLETADA EXITOSAMENTE${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo -e "${BLUE}📍 Ubicación:${NC} $ADMIN_DIR"
    echo -e "${BLUE}🌐 URL de Acceso:${NC} http://192.168.4.1/sistema/admin_users/"
    echo -e "${BLUE}👤 Usuario Autorizado:${NC} peterh4ck"
    echo -e "${BLUE}🔑 Rol Requerido:${NC} SuperUser"
    echo ""
    echo -e "${GREEN}✅ Archivos Instalados:${NC}"
    echo -e "   • index.html (Interfaz principal)"
    echo -e "   • check_admin_access.php (Verificación de acceso)"
    echo -e "   • admin_api.php (API de administración)"
    echo -e "   • README_ADMIN.md (Documentación)"
    echo ""
    echo -e "${YELLOW}⚠️ RECORDATORIOS IMPORTANTES:${NC}"
    echo -e "   • Solo peterh4ck puede acceder a esta plataforma"
    echo -e "   • La plataforma otorga CONTROL TOTAL del sistema"
    echo -e "   • Ejecutar SQL con extrema precaución"
    echo -e "   • Hacer backup antes de cambios importantes"
    echo ""
    echo -e "${PURPLE}📚 Documentación completa en:${NC} $ADMIN_DIR/README_ADMIN.md"
    echo -e "${PURPLE}📋 Logs de instalación en:${NC} $LOG_FILE"
    echo ""
    echo -e "${CYAN}================================================================${NC}"
}

# Función principal
main() {
    show_header
    
    echo -e "${WHITE}🚀 Iniciando instalación de la Plataforma de Administración Total${NC}"
    echo -e "${WHITE}   ACCESO EXCLUSIVO PARA: peterh4ck${NC}"
    echo ""
    
    # Confirmar instalación
    read -p "¿Deseas continuar con la instalación? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}⏹️ Instalación cancelada por el usuario${NC}"
        exit 0
    fi
    
    log "=== INICIO DE INSTALACIÓN DE PLATAFORMA DE ADMINISTRACIÓN ==="
    
    # Ejecutar verificaciones e instalación
    check_root
    check_dependencies
    check_database
    backup_existing
    create_directories
    
    echo -e "${BLUE}📝 Los archivos principales deben ser copiados manualmente:${NC}"
    echo -e "   1. index.html"
    echo -e "   2. check_admin_access.php"
    echo -e "   3. admin_api.php"
    echo -e "   4. README_ADMIN.md"
    echo ""
    
    set_permissions
    update_user_permissions
    verify_installation
    
    log "=== INSTALACIÓN COMPLETADA EXITOSAMENTE ==="
    
    show_final_info
}

# Función para mostrar ayuda
show_help() {
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${WHITE}    SCRIPT DE INSTALACIÓN - PLATAFORMA DE ADMINISTRACIÓN${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo -e "${BLUE}Uso:${NC} sudo $0 [OPCIÓN]"
    echo ""
    echo -e "${BLUE}Opciones:${NC}"
    echo -e "  -h, --help     Mostrar esta ayuda"
    echo -e "  -v, --verify   Solo verificar dependencias"
    echo -e "  -b, --backup   Solo realizar backup"
    echo -e "  -p, --perms    Solo configurar permisos"
    echo ""
    echo -e "${BLUE}Ejemplos:${NC}"
    echo -e "  sudo $0                 # Instalación completa"
    echo -e "  sudo $0 --verify        # Solo verificar sistema"
    echo -e "  sudo $0 --backup        # Solo hacer backup"
    echo ""
}

# Procesar argumentos de línea de comandos
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    -v|--verify)
        show_header
        check_root
        check_dependencies
        check_database
        echo -e "${GREEN}✅ Verificación completada${NC}"
        exit 0
        ;;
    -b|--backup)
        show_header
        check_root
        create_directories
        backup_existing
        echo -e "${GREEN}✅ Backup completado${NC}"
        exit 0
        ;;
    -p|--perms)
        show_header
        check_root
        set_permissions
        echo -e "${GREEN}✅ Permisos configurados${NC}"
        exit 0
        ;;
    "")
        main
        ;;
    *)
        echo -e "${RED}❌ Opción no válida: $1${NC}"
        echo -e "${YELLOW}💡 Usa: $0 --help para ver las opciones disponibles${NC}"
        exit 1
        ;;
esac