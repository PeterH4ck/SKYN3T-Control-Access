/**
 * MODALES Y FORMULARIOS AVANZADOS - PLATAFORMA DE ADMINISTRACIÓN SKYN3T
 * Sistema completo de modales para gestión de usuarios, roles, BD y sistema
 * Versión: 3.0.1 - Solo para peterh4ck
 */

// Clase principal para gestión de modales
class AdminModals {
    constructor() {
        this.activeModal = null;
        this.initializeEventListeners();
    }

    // Inicializar event listeners globales
    initializeEventListeners() {
        // Cerrar modales con Escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.activeModal) {
                this.closeModal(this.activeModal);
            }
        });

        // Cerrar modales al hacer clic fuera
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal-overlay')) {
                this.closeModal(this.activeModal);
            }
        });
    }

    // Abrir modal genérico
    openModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = 'flex';
            this.activeModal = modalId;
            document.body.style.overflow = 'hidden';
        }
    }

    // Cerrar modal
    closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = 'none';
            this.activeModal = null;
            document.body.style.overflow = 'auto';
        }
    }

    // Crear estructura base de modal
    createModalStructure(id, title, content, actions = '') {
        return `
            <div id="${id}" class="modal-overlay" style="display: none;">
                <div class="modal-container">
                    <div class="modal-header">
                        <h3 class="modal-title">
                            <i class="fas fa-shield-alt"></i> ${title}
                        </h3>
                        <button class="modal-close" onclick="adminModals.closeModal('${id}')">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <div class="modal-content">
                        ${content}
                    </div>
                    ${actions ? `<div class="modal-actions">${actions}</div>` : ''}
                </div>
            </div>
        `;
    }

    // Modal para agregar usuario
    showAddUserModal() {
        const modalHtml = this.createModalStructure('add-user-modal', 'Agregar Nuevo Usuario', `
            <form id="add-user-form" class="admin-form">
                <div class="alert info">
                    <i class="fas fa-info-circle"></i>
                    <span>Creando nuevo usuario en el sistema SKYN3T. Solo peterh4ck puede realizar esta operación.</span>
                </div>
                
                <div class="form-grid">
                    <div class="form-group">
                        <label class="form-label">Nombre de Usuario *</label>
                        <input type="text" name="username" class="form-input" required 
                               placeholder="Ej: nuevo_admin" maxlength="50">
                        <small class="form-help">Solo letras, números y guiones bajos</small>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Contraseña *</label>
                        <input type="password" name="password" class="form-input" required 
                               placeholder="Contraseña segura" minlength="8">
                        <small class="form-help">Mínimo 8 caracteres</small>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Confirmar Contraseña *</label>
                        <input type="password" name="confirm_password" class="form-input" required 
                               placeholder="Confirmar contraseña">
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Rol del Usuario *</label>
                        <select name="role" class="form-select" required>
                            <option value="">Seleccionar rol...</option>
                            <option value="User">👤 User - Acceso básico</option>
                            <option value="SupportAdmin">🛠️ SupportAdmin - Soporte técnico</option>
                            <option value="Admin">👑 Admin - Administración general</option>
                            <option value="SuperUser">⚡ SuperUser - Control total (¡PELIGROSO!)</option>
                        </select>
                        <small class="form-help">Selecciona cuidadosamente el nivel de acceso</small>
                    </div>
                </div>
                
                <div class="form-group">
                    <label class="checkbox-container">
                        <input type="checkbox" name="active" checked>
                        <span class="checkmark"></span>
                        Usuario activo al crear
                    </label>
                </div>
                
                <div class="permissions-preview" id="permissions-preview">
                    <!-- Se llenará dinámicamente según el rol seleccionado -->
                </div>
            </form>
        `, `
            <button type="button" class="btn secondary" onclick="adminModals.closeModal('add-user-modal')">
                <i class="fas fa-times"></i> Cancelar
            </button>
            <button type="submit" form="add-user-form" class="btn success">
                <i class="fas fa-user-plus"></i> Crear Usuario
            </button>
        `);

        this.injectModal(modalHtml);
        this.openModal('add-user-modal');
        this.setupAddUserForm();
    }

    // Modal para editar usuario
    showEditUserModal(userId) {
        // Cargar datos del usuario primero
        this.loadUserData(userId).then(userData => {
            const modalHtml = this.createModalStructure('edit-user-modal', `Editar Usuario: ${userData.username}`, `
                <form id="edit-user-form" class="admin-form">
                    <input type="hidden" name="user_id" value="${userData.id}">
                    
                    ${userData.username === 'peterh4ck' ? `
                        <div class="alert warning">
                            <i class="fas fa-crown"></i>
                            <span>Editando cuenta del ADMINISTRADOR PRINCIPAL. ¡Extrema precaución!</span>
                        </div>
                    ` : ''}
                    
                    <div class="form-grid">
                        <div class="form-group">
                            <label class="form-label">Nombre de Usuario</label>
                            <input type="text" name="username" class="form-input" 
                                   value="${userData.username}" readonly>
                            <small class="form-help">El nombre de usuario no se puede cambiar</small>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Rol Actual</label>
                            <select name="role" class="form-select" ${userData.username === 'peterh4ck' ? 'disabled' : ''}>
                                <option value="User" ${userData.role === 'User' ? 'selected' : ''}>👤 User</option>
                                <option value="SupportAdmin" ${userData.role === 'SupportAdmin' ? 'selected' : ''}>🛠️ SupportAdmin</option>
                                <option value="Admin" ${userData.role === 'Admin' ? 'selected' : ''}>👑 Admin</option>
                                <option value="SuperUser" ${userData.role === 'SuperUser' ? 'selected' : ''}>⚡ SuperUser</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Estado</label>
                            <select name="active" class="form-select" ${userData.username === 'peterh4ck' ? 'disabled' : ''}>
                                <option value="1" ${userData.active ? 'selected' : ''}>✅ Activo</option>
                                <option value="0" ${!userData.active ? 'selected' : ''}>❌ Inactivo</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Nueva Contraseña</label>
                            <input type="password" name="new_password" class="form-input" 
                                   placeholder="Dejar vacío para mantener actual">
                            <small class="form-help">Solo completar si deseas cambiar la contraseña</small>
                        </div>
                    </div>
                    
                    <div class="user-stats">
                        <h4>📊 Estadísticas del Usuario</h4>
                        <div class="stats-grid">
                            <div class="stat-item">
                                <span class="stat-label">Último Login:</span>
                                <span class="stat-value">${userData.last_login ? new Date(userData.last_login).toLocaleString('es-ES') : 'Nunca'}</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">Creado:</span>
                                <span class="stat-value">${new Date(userData.created_at).toLocaleString('es-ES')}</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">Intentos de Login:</span>
                                <span class="stat-value">${userData.login_attempts || 0}</span>
                            </div>
                        </div>
                    </div>
                </form>
            `, `
                <button type="button" class="btn secondary" onclick="adminModals.closeModal('edit-user-modal')">
                    <i class="fas fa-times"></i> Cancelar
                </button>
                ${userData.username !== 'peterh4ck' ? `
                    <button type="button" class="btn danger" onclick="adminModals.confirmDeleteUser(${userData.id}, '${userData.username}')">
                        <i class="fas fa-trash"></i> Eliminar Usuario
                    </button>
                ` : ''}
                <button type="submit" form="edit-user-form" class="btn primary">
                    <i class="fas fa-save"></i> Guardar Cambios
                </button>
            `);

            this.injectModal(modalHtml);
            this.openModal('edit-user-modal');
            this.setupEditUserForm();
        });
    }

    // Modal para consola SQL
    showSQLConsoleModal() {
        const modalHtml = this.createModalStructure('sql-console-modal', '⚠️ CONSOLA SQL - CONTROL TOTAL DE BASE DE DATOS', `
            <div class="alert danger">
                <i class="fas fa-exclamation-triangle"></i>
                <span><strong>¡PELIGRO!</strong> Esta consola permite ejecutar CUALQUIER comando SQL. Un error puede destruir todo el sistema.</span>
            </div>
            
            <div class="sql-console">
                <div class="console-header">
                    <h4>🗄️ Base de Datos: skyn3t_db</h4>
                    <div class="console-controls">
                        <button type="button" class="btn small" onclick="adminModals.loadSQLTemplates()">
                            <i class="fas fa-code"></i> Plantillas
                        </button>
                        <button type="button" class="btn small warning" onclick="adminModals.clearSQLConsole()">
                            <i class="fas fa-eraser"></i> Limpiar
                        </button>
                    </div>
                </div>
                
                <form id="sql-console-form">
                    <div class="form-group">
                        <label class="form-label">Comando SQL:</label>
                        <textarea name="sql_query" id="sql-query" class="form-textarea" rows="8" 
                                  placeholder="-- Escribe tu consulta SQL aquí
-- Ejemplos:
-- SELECT * FROM users;
-- SHOW TABLES;
-- DESCRIBE users;
-- 
-- ⚠️ CUIDADO CON: DROP, DELETE, UPDATE sin WHERE
" required></textarea>
                    </div>
                    
                    <div class="sql-options">
                        <label class="checkbox-container">
                            <input type="checkbox" name="confirm_execution" required>
                            <span class="checkmark"></span>
                            Confirmo que he revisado el comando y entiendo las consecuencias
                        </label>
                    </div>
                </form>
                
                <div id="sql-results" class="sql-results" style="display: none;">
                    <!-- Resultados se mostrarán aquí -->
                </div>
            </div>
        `, `
            <button type="button" class="btn secondary" onclick="adminModals.closeModal('sql-console-modal')">
                <i class="fas fa-times"></i> Cerrar
            </button>
            <button type="submit" form="sql-console-form" class="btn danger">
                <i class="fas fa-database"></i> Ejecutar SQL
            </button>
        `);

        this.injectModal(modalHtml);
        this.openModal('sql-console-modal');
        this.setupSQLConsole();
    }

    // Modal para ver estructura de tabla
    showTableStructureModal(tableName) {
        const modalHtml = this.createModalStructure('table-structure-modal', `Estructura de Tabla: ${tableName}`, `
            <div class="table-info">
                <div class="loading" id="table-structure-loading">
                    <div class="spinner"></div>
                    <span>Cargando estructura de ${tableName}...</span>
                </div>
                
                <div id="table-structure-content" style="display: none;">
                    <!-- Contenido se cargará dinámicamente -->
                </div>
            </div>
        `, `
            <button type="button" class="btn secondary" onclick="adminModals.closeModal('table-structure-modal')">
                <i class="fas fa-times"></i> Cerrar
            </button>
            <button type="button" class="btn primary" onclick="adminModals.exportTableStructure('${tableName}')">
                <i class="fas fa-download"></i> Exportar Estructura
            </button>
        `);

        this.injectModal(modalHtml);
        this.openModal('table-structure-modal');
        this.loadTableStructure(tableName);
    }

    // Modal para gestión de roles
    showRoleManagementModal() {
        const modalHtml = this.createModalStructure('role-management-modal', 'Gestión de Roles y Permisos', `
            <div class="roles-management">
                <div class="alert info">
                    <i class="fas fa-info-circle"></i>
                    <span>Gestiona los roles del sistema y sus permisos. Los cambios se aplicarán inmediatamente.</span>
                </div>
                
                <div class="roles-grid" id="roles-grid">
                    <div class="loading">
                        <div class="spinner"></div>
                        <span>Cargando roles del sistema...</span>
                    </div>
                </div>
            </div>
        `, `
            <button type="button" class="btn secondary" onclick="adminModals.closeModal('role-management-modal')">
                <i class="fas fa-times"></i> Cerrar
            </button>
            <button type="button" class="btn success" onclick="adminModals.saveRoleChanges()">
                <i class="fas fa-save"></i> Guardar Cambios
            </button>
        `);

        this.injectModal(modalHtml);
        this.openModal('role-management-modal');
        this.loadRoleManagement();
    }

    // Modal de confirmación para eliminar usuario
    confirmDeleteUser(userId, username) {
        if (username === 'peterh4ck') {
            this.showAlert('error', '¡No se puede eliminar la cuenta del administrador principal!');
            return;
        }

        const modalHtml = this.createModalStructure('confirm-delete-modal', '⚠️ Confirmar Eliminación', `
            <div class="alert danger">
                <i class="fas fa-exclamation-triangle"></i>
                <span><strong>¡ADVERTENCIA!</strong> Esta acción es IRREVERSIBLE.</span>
            </div>
            
            <div class="confirm-content">
                <h4>¿Estás seguro de que quieres eliminar al usuario?</h4>
                <div class="user-info-delete">
                    <div class="user-avatar">${username.charAt(0).toUpperCase()}</div>
                    <div class="user-details">
                        <strong>${username}</strong>
                        <span>ID: ${userId}</span>
                    </div>
                </div>
                
                <p>Se eliminarán:</p>
                <ul>
                    <li>✗ Cuenta de usuario</li>
                    <li>✗ Todas las sesiones activas</li>
                    <li>✗ Permisos y privilegios</li>
                    <li>✗ Configuraciones personales</li>
                </ul>
                
                <div class="form-group">
                    <label class="form-label">Escribe "${username}" para confirmar:</label>
                    <input type="text" id="delete-confirmation" class="form-input" 
                           placeholder="Escribir nombre de usuario">
                </div>
            </div>
        `, `
            <button type="button" class="btn secondary" onclick="adminModals.closeModal('confirm-delete-modal')">
                <i class="fas fa-times"></i> Cancelar
            </button>
            <button type="button" class="btn danger" onclick="adminModals.executeDeleteUser(${userId}, '${username}')" id="confirm-delete-btn" disabled>
                <i class="fas fa-trash"></i> ELIMINAR USUARIO
            </button>
        `);

        this.injectModal(modalHtml);
        this.openModal('confirm-delete-modal');
        this.setupDeleteConfirmation(username);
    }

    // Modal para información del sistema
    showSystemInfoModal() {
        const modalHtml = this.createModalStructure('system-info-modal', 'Información del Sistema', `
            <div class="system-info">
                <div class="loading" id="system-info-loading">
                    <div class="spinner"></div>
                    <span>Recopilando información del sistema...</span>
                </div>
                
                <div id="system-info-content" style="display: none;">
                    <!-- Contenido se cargará dinámicamente -->
                </div>
            </div>
        `, `
            <button type="button" class="btn secondary" onclick="adminModals.closeModal('system-info-modal')">
                <i class="fas fa-times"></i> Cerrar
            </button>
            <button type="button" class="btn primary" onclick="adminModals.exportSystemInfo()">
                <i class="fas fa-download"></i> Exportar Info
            </button>
        `);

        this.injectModal(modalHtml);
        this.openModal('system-info-modal');
        this.loadSystemInfo();
    }

    // Inyectar modal en el DOM
    injectModal(modalHtml) {
        // Remover modal existente si existe
        const existingModals = document.querySelectorAll('.modal-overlay');
        existingModals.forEach(modal => modal.remove());

        // Agregar nuevo modal
        document.body.insertAdjacentHTML('beforeend', modalHtml);
    }

    // Mostrar alerta
    showAlert(type, message, duration = 5000) {
        const alertHtml = `
            <div class="alert-notification ${type}" id="alert-${Date.now()}">
                <div class="alert-content">
                    <i class="fas ${this.getAlertIcon(type)}"></i>
                    <span>${message}</span>
                </div>
                <button class="alert-close" onclick="this.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', alertHtml);

        // Auto-remover después del tiempo especificado
        if (duration > 0) {
            setTimeout(() => {
                const alert = document.getElementById(`alert-${Date.now()}`);
                if (alert) alert.remove();
            }, duration);
        }
    }

    // Obtener icono para alertas
    getAlertIcon(type) {
        const icons = {
            'success': 'fa-check-circle',
            'error': 'fa-exclamation-circle',
            'warning': 'fa-exclamation-triangle',
            'info': 'fa-info-circle'
        };
        return icons[type] || 'fa-info-circle';
    }

    // Configurar formulario de agregar usuario
    setupAddUserForm() {
        const form = document.getElementById('add-user-form');
        const roleSelect = form.querySelector('[name="role"]');
        const previewDiv = document.getElementById('permissions-preview');

        // Actualizar preview de permisos cuando cambie el rol
        roleSelect.addEventListener('change', () => {
            this.updatePermissionsPreview(roleSelect.value, previewDiv);
        });

        // Validación de contraseñas
        const passwordInput = form.querySelector('[name="password"]');
        const confirmInput = form.querySelector('[name="confirm_password"]');

        confirmInput.addEventListener('input', () => {
            if (passwordInput.value !== confirmInput.value) {
                confirmInput.setCustomValidity('Las contraseñas no coinciden');
            } else {
                confirmInput.setCustomValidity('');
            }
        });

        // Manejar envío del formulario
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAddUser(form);
        });
    }

    // Actualizar preview de permisos
    updatePermissionsPreview(role, container) {
        const permissions = {
            'User': ['dashboard', 'relay'],
            'SupportAdmin': ['dashboard', 'devices', 'relay', 'logs'],
            'Admin': ['dashboard', 'devices', 'users', 'relay', 'logs'],
            'SuperUser': ['all', 'dashboard', 'devices', 'users', 'relay', 'logs', 'system', 'database']
        };

        if (!role || !permissions[role]) {
            container.innerHTML = '';
            return;
        }

        const rolePerms = permissions[role];
        container.innerHTML = `
            <div class="permissions-preview-content">
                <h4>🔐 Permisos que se otorgarán:</h4>
                <div class="permissions-list">
                    ${rolePerms.map(perm => `
                        <span class="permission-tag ${perm === 'all' ? 'danger' : 'info'}">
                            ${perm === 'all' ? '⚡' : '✓'} ${perm}
                        </span>
                    `).join('')}
                </div>
                ${role === 'SuperUser' ? `
                    <div class="alert warning">
                        <i class="fas fa-exclamation-triangle"></i>
                        <span><strong>¡CUIDADO!</strong> SuperUser tiene acceso total al sistema, incluyendo base de datos.</span>
                    </div>
                ` : ''}
            </div>
        `;
    }

    // Cargar datos de usuario
    async loadUserData(userId) {
        try {
            const response = await fetch(`admin_api.php?action=get_user&id=${userId}`, {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            const data = await response.json();
            if (data.success) {
                return data.user;
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            console.error('Error cargando datos de usuario:', error);
            this.showAlert('error', 'Error al cargar datos del usuario');
            return null;
        }
    }

    // Manejar creación de usuario
    async handleAddUser(form) {
        const formData = new FormData(form);
        const userData = Object.fromEntries(formData.entries());

        try {
            const response = await fetch('admin_api.php?action=create_user', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify(userData)
            });

            const data = await response.json();
            if (data.success) {
                this.showAlert('success', `Usuario "${userData.username}" creado exitosamente`);
                this.closeModal('add-user-modal');
                // Recargar tabla de usuarios
                if (typeof loadUsersContent === 'function') {
                    loadUsersContent();
                }
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            console.error('Error creando usuario:', error);
            this.showAlert('error', 'Error al crear usuario: ' + error.message);
        }
    }

    // Configurar confirmación de eliminación
    setupDeleteConfirmation(username) {
        const input = document.getElementById('delete-confirmation');
        const button = document.getElementById('confirm-delete-btn');

        input.addEventListener('input', () => {
            button.disabled = input.value !== username;
        });
    }

    // Más métodos se implementarán según necesidad...
}

// Instancia global
const adminModals = new AdminModals();

// Estilos CSS adicionales para modales
const modalStyles = `
<style>
.modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.8);
    z-index: 10000;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    backdrop-filter: blur(5px);
}

.modal-container {
    background: rgba(55, 65, 79, 0.95);
    backdrop-filter: blur(20px);
    border: 2px solid rgba(33, 153, 234, 0.3);
    border-radius: 20px;
    max-width: 90vw;
    max-height: 90vh;
    width: 100%;
    overflow-y: auto;
    position: relative;
}

.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px 30px;
    border-bottom: 1px solid rgba(33, 153, 234, 0.2);
}

.modal-title {
    color: #ffffff;
    font-size: 20px;
    font-weight: 600;
    margin: 0;
}

.modal-close {
    background: none;
    border: none;
    color: rgba(255, 255, 255, 0.7);
    font-size: 20px;
    cursor: pointer;
    transition: color 0.3s ease;
    padding: 5px;
}

.modal-close:hover {
    color: #dc3545;
}

.modal-content {
    padding: 30px;
}

.modal-actions {
    display: flex;
    gap: 15px;
    justify-content: flex-end;
    padding: 20px 30px;
    border-top: 1px solid rgba(33, 153, 234, 0.2);
}

.admin-form {
    max-width: none;
}

.form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-bottom: 20px;
}

.form-help {
    color: rgba(255, 255, 255, 0.6);
    font-size: 12px;
    margin-top: 5px;
    display: block;
}

.permissions-preview-content {
    margin-top: 20px;
    padding: 20px;
    background: rgba(33, 153, 234, 0.1);
    border-radius: 10px;
    border: 1px solid rgba(33, 153, 234, 0.2);
}

.permissions-list {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin: 15px 0;
}

.permission-tag {
    padding: 4px 10px;
    border-radius: 15px;
    font-size: 12px;
    font-weight: 600;
}

.permission-tag.info {
    background: rgba(33, 153, 234, 0.2);
    color: #2199ea;
    border: 1px solid rgba(33, 153, 234, 0.3);
}

.permission-tag.danger {
    background: rgba(220, 53, 69, 0.2);
    color: #dc3545;
    border: 1px solid rgba(220, 53, 69, 0.3);
}

.checkbox-container {
    display: flex;
    align-items: center;
    gap: 10px;
    cursor: pointer;
    color: rgba(255, 255, 255, 0.9);
}

.sql-console {
    min-height: 400px;
}

.console-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding-bottom: 15px;
    border-bottom: 1px solid rgba(33, 153, 234, 0.2);
}

.console-controls {
    display: flex;
    gap: 10px;
}

.form-textarea {
    width: 100%;
    padding: 15px;
    background: rgba(0, 0, 0, 0.3);
    border: 2px solid rgba(33, 153, 234, 0.3);
    border-radius: 10px;
    color: #ffffff;
    font-family: 'Courier New', monospace;
    font-size: 14px;
    line-height: 1.5;
    resize: vertical;
    min-height: 200px;
}

.sql-results {
    margin-top: 20px;
    padding: 20px;
    background: rgba(0, 0, 0, 0.2);
    border-radius: 10px;
    border: 1px solid rgba(33, 153, 234, 0.2);
    max-height: 300px;
    overflow-y: auto;
}

.user-info-delete {
    display: flex;
    align-items: center;
    gap: 15px;
    margin: 20px 0;
    padding: 15px;
    background: rgba(220, 53, 69, 0.1);
    border-radius: 10px;
    border: 1px solid rgba(220, 53, 69, 0.3);
}

.user-avatar {
    width: 50px;
    height: 50px;
    border-radius: 50%;
    background: linear-gradient(135deg, #dc3545, #c82333);
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-weight: 600;
    font-size: 20px;
}

.alert-notification {
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 10001;
    padding: 15px 20px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 300px;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
    animation: slideInRight 0.3s ease-out;
}

.alert-notification.success {
    background: rgba(40, 167, 69, 0.9);
    border: 1px solid #28a745;
    color: white;
}

.alert-notification.error {
    background: rgba(220, 53, 69, 0.9);
    border: 1px solid #dc3545;
    color: white;
}

.alert-notification.warning {
    background: rgba(255, 193, 7, 0.9);
    border: 1px solid #ffc107;
    color: #212529;
}

.alert-notification.info {
    background: rgba(33, 153, 234, 0.9);
    border: 1px solid #2199ea;
    color: white;
}

.alert-close {
    background: none;
    border: none;
    color: inherit;
    cursor: pointer;
    font-size: 16px;
    margin-left: auto;
}

@keyframes slideInRight {
    from {
        transform: translateX(100%);
        opacity: 0;
    }
    to {
        transform: translateX(0);
        opacity: 1;
    }
}

@media (max-width: 768px) {
    .modal-container {
        max-width: 95vw;
        margin: 10px;
    }
    
    .form-grid {
        grid-template-columns: 1fr;
    }
    
    .alert-notification {
        min-width: auto;
        max-width: 90vw;
        right: 5%;
    }
}
</style>
`;

// Inyectar estilos
document.head.insertAdjacentHTML('beforeend', modalStyles);