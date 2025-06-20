/**
 * SISTEMA DE MONITOREO EN TIEMPO REAL - SKYN3T
 * Monitoreo avanzado del sistema para la plataforma de administración
 * Versión: 3.0.1 - Solo para peterh4ck
 */

class RealTimeMonitor {
    constructor() {
        this.isActive = false;
        this.intervals = new Map();
        this.charts = new Map();
        this.alerts = [];
        this.thresholds = {
            cpu_usage: 80,
            memory_usage: 85,
            disk_usage: 90,
            session_limit: 100,
            failed_logins: 5
        };
        
        this.initializeMonitor();
    }

    // Inicializar sistema de monitoreo
    initializeMonitor() {
        console.log('🔍 Inicializando sistema de monitoreo en tiempo real...');
        
        // Crear contenedor de monitoreo si no existe
        this.createMonitoringInterface();
        
        // Configurar event listeners
        this.setupEventListeners();
        
        console.log('✅ Sistema de monitoreo inicializado');
    }

    // Crear interfaz de monitoreo
    createMonitoringInterface() {
        const monitorHtml = `
            <div id="realtime-monitor" class="monitor-overlay" style="display: none;">
                <div class="monitor-container">
                    <div class="monitor-header">
                        <h3 class="monitor-title">
                            <i class="fas fa-chart-line"></i> Monitoreo en Tiempo Real
                        </h3>
                        <div class="monitor-controls">
                            <span class="monitor-status" id="monitor-status">
                                <span class="status-dot"></span> Conectado
                            </span>
                            <button class="monitor-btn" onclick="realtimeMonitor.toggleMonitor()">
                                <i class="fas fa-pause" id="monitor-toggle-icon"></i>
                            </button>
                            <button class="monitor-btn" onclick="realtimeMonitor.closeMonitor()">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                    </div>
                    
                    <div class="monitor-content">
                        <!-- Panel de métricas principales -->
                        <div class="metrics-grid">
                            <div class="metric-card" data-metric="system">
                                <div class="metric-header">
                                    <i class="fas fa-server"></i>
                                    <span>Sistema</span>
                                </div>
                                <div class="metric-value" id="system-load">--</div>
                                <div class="metric-label">Carga del Sistema</div>
                            </div>
                            
                            <div class="metric-card" data-metric="memory">
                                <div class="metric-header">
                                    <i class="fas fa-memory"></i>
                                    <span>Memoria</span>
                                </div>
                                <div class="metric-value" id="memory-usage">--</div>
                                <div class="metric-label">Uso de RAM</div>
                            </div>
                            
                            <div class="metric-card" data-metric="database">
                                <div class="metric-header">
                                    <i class="fas fa-database"></i>
                                    <span>Base de Datos</span>
                                </div>
                                <div class="metric-value" id="db-connections">--</div>
                                <div class="metric-label">Conexiones Activas</div>
                            </div>
                            
                            <div class="metric-card" data-metric="sessions">
                                <div class="metric-header">
                                    <i class="fas fa-users"></i>
                                    <span>Sesiones</span>
                                </div>
                                <div class="metric-value" id="active-sessions">--</div>
                                <div class="metric-label">Usuarios Conectados</div>
                            </div>
                        </div>
                        
                        <!-- Panel de alertas -->
                        <div class="alerts-panel">
                            <div class="panel-header">
                                <h4><i class="fas fa-exclamation-triangle"></i> Alertas del Sistema</h4>
                                <button class="btn small" onclick="realtimeMonitor.clearAlerts()">
                                    <i class="fas fa-trash"></i> Limpiar
                                </button>
                            </div>
                            <div class="alerts-list" id="alerts-list">
                                <div class="no-alerts">
                                    <i class="fas fa-check-circle"></i>
                                    <span>No hay alertas activas</span>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Panel de gráficos -->
                        <div class="charts-panel">
                            <div class="panel-header">
                                <h4><i class="fas fa-chart-area"></i> Gráficos en Tiempo Real</h4>
                                <div class="chart-controls">
                                    <select id="chart-timeframe" class="chart-select">
                                        <option value="5">Últimos 5 min</option>
                                        <option value="15" selected>Últimos 15 min</option>
                                        <option value="30">Últimos 30 min</option>
                                        <option value="60">Última hora</option>
                                    </select>
                                </div>
                            </div>
                            <div class="charts-grid">
                                <div class="chart-container">
                                    <canvas id="system-chart" width="400" height="200"></canvas>
                                </div>
                                <div class="chart-container">
                                    <canvas id="sessions-chart" width="400" height="200"></canvas>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Panel de actividad reciente -->
                        <div class="activity-panel">
                            <div class="panel-header">
                                <h4><i class="fas fa-list"></i> Actividad Reciente</h4>
                                <span class="activity-count" id="activity-count">0 eventos</span>
                            </div>
                            <div class="activity-list" id="activity-list">
                                <div class="loading-activity">
                                    <div class="spinner small"></div>
                                    <span>Cargando actividad...</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Inyectar interfaz en el DOM
        document.body.insertAdjacentHTML('beforeend', monitorHtml);
    }

    // Configurar event listeners
    setupEventListeners() {
        // Cambio de timeframe para gráficos
        document.getElementById('chart-timeframe')?.addEventListener('change', (e) => {
            this.updateChartTimeframe(e.target.value);
        });

        // Atajos de teclado
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.shiftKey && e.key === 'M') {
                e.preventDefault();
                this.toggleMonitorVisibility();
            }
        });
    }

    // Mostrar/ocultar monitor
    toggleMonitorVisibility() {
        const monitor = document.getElementById('realtime-monitor');
        if (monitor.style.display === 'none') {
            this.showMonitor();
        } else {
            this.closeMonitor();
        }
    }

    // Mostrar monitor
    showMonitor() {
        const monitor = document.getElementById('realtime-monitor');
        monitor.style.display = 'flex';
        
        if (!this.isActive) {
            this.startMonitoring();
        }
        
        this.initializeCharts();
    }

    // Cerrar monitor
    closeMonitor() {
        const monitor = document.getElementById('realtime-monitor');
        monitor.style.display = 'none';
        this.stopMonitoring();
    }

    // Iniciar monitoreo
    startMonitoring() {
        console.log('🚀 Iniciando monitoreo en tiempo real...');
        this.isActive = true;

        // Actualizar estado visual
        this.updateMonitorStatus('Conectado', 'connected');

        // Configurar intervalos de actualización
        this.intervals.set('metrics', setInterval(() => {
            this.updateMetrics();
        }, 5000)); // Cada 5 segundos

        this.intervals.set('alerts', setInterval(() => {
            this.checkAlerts();
        }, 10000)); // Cada 10 segundos

        this.intervals.set('activity', setInterval(() => {
            this.updateActivity();
        }, 15000)); // Cada 15 segundos

        this.intervals.set('charts', setInterval(() => {
            this.updateCharts();
        }, 30000)); // Cada 30 segundos

        // Primera carga inmediata
        this.updateMetrics();
        this.updateActivity();
    }

    // Detener monitoreo
    stopMonitoring() {
        console.log('⏹️ Deteniendo monitoreo...');
        this.isActive = false;

        // Limpiar intervalos
        this.intervals.forEach((interval, key) => {
            clearInterval(interval);
        });
        this.intervals.clear();

        // Actualizar estado visual
        this.updateMonitorStatus('Desconectado', 'disconnected');
    }

    // Alternar monitoreo
    toggleMonitor() {
        if (this.isActive) {
            this.stopMonitoring();
            document.getElementById('monitor-toggle-icon').className = 'fas fa-play';
        } else {
            this.startMonitoring();
            document.getElementById('monitor-toggle-icon').className = 'fas fa-pause';
        }
    }

    // Actualizar estado del monitor
    updateMonitorStatus(text, status) {
        const statusElement = document.getElementById('monitor-status');
        if (statusElement) {
            statusElement.innerHTML = `<span class="status-dot ${status}"></span> ${text}`;
        }
    }

    // Actualizar métricas principales
    async updateMetrics() {
        try {
            const response = await fetch('monitor_api.php?action=system_metrics', {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            const data = await response.json();
            
            if (data.success) {
                const metrics = data.metrics;
                
                // Actualizar métricas en la interfaz
                this.updateMetricCard('system-load', metrics.system_load || '--', 'system');
                this.updateMetricCard('memory-usage', `${metrics.memory_usage || 0}%`, 'memory');
                this.updateMetricCard('db-connections', metrics.db_connections || '--', 'database');
                this.updateMetricCard('active-sessions', metrics.active_sessions || 0, 'sessions');
                
                // Verificar umbrales para alertas
                this.checkMetricThresholds(metrics);
            }
        } catch (error) {
            console.error('Error actualizando métricas:', error);
            this.addAlert('error', 'Error al obtener métricas del sistema');
        }
    }

    // Actualizar tarjeta de métrica
    updateMetricCard(elementId, value, metricType) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = value;
            
            // Actualizar estado visual basado en el valor
            const card = element.closest('.metric-card');
            card.className = 'metric-card ' + this.getMetricStatus(value, metricType);
        }
    }

    // Obtener estado de métrica
    getMetricStatus(value, metricType) {
        const numericValue = parseInt(value);
        
        switch (metricType) {
            case 'memory':
                if (numericValue > 85) return 'critical';
                if (numericValue > 70) return 'warning';
                return 'normal';
            case 'system':
                if (numericValue > 80) return 'critical';
                if (numericValue > 60) return 'warning';
                return 'normal';
            case 'database':
                if (numericValue > 50) return 'warning';
                return 'normal';
            default:
                return 'normal';
        }
    }

    // Verificar umbrales de métricas
    checkMetricThresholds(metrics) {
        // Verificar uso de memoria
        if (metrics.memory_usage > this.thresholds.memory_usage) {
            this.addAlert('warning', `Uso de memoria alto: ${metrics.memory_usage}%`);
        }

        // Verificar carga del sistema
        if (metrics.system_load > this.thresholds.cpu_usage) {
            this.addAlert('warning', `Carga del sistema alta: ${metrics.system_load}%`);
        }

        // Verificar sesiones activas
        if (metrics.active_sessions > this.thresholds.session_limit) {
            this.addAlert('warning', `Muchas sesiones activas: ${metrics.active_sessions}`);
        }
    }

    // Verificar alertas del sistema
    async checkAlerts() {
        try {
            const response = await fetch('monitor_api.php?action=system_alerts', {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            const data = await response.json();
            
            if (data.success && data.alerts) {
                data.alerts.forEach(alert => {
                    this.addAlert(alert.level, alert.message, alert.timestamp);
                });
            }
        } catch (error) {
            console.error('Error verificando alertas:', error);
        }
    }

    // Agregar alerta
    addAlert(level, message, timestamp = null) {
        const alertId = Date.now();
        const alert = {
            id: alertId,
            level: level,
            message: message,
            timestamp: timestamp || new Date().toLocaleTimeString('es-ES'),
            created_at: Date.now()
        };

        this.alerts.unshift(alert);

        // Limitar número de alertas en memoria
        if (this.alerts.length > 50) {
            this.alerts = this.alerts.slice(0, 50);
        }

        this.renderAlerts();

        // Auto-remover alertas info después de 30 segundos
        if (level === 'info') {
            setTimeout(() => {
                this.removeAlert(alertId);
            }, 30000);
        }
    }

    // Renderizar alertas
    renderAlerts() {
        const alertsList = document.getElementById('alerts-list');
        
        if (this.alerts.length === 0) {
            alertsList.innerHTML = `
                <div class="no-alerts">
                    <i class="fas fa-check-circle"></i>
                    <span>No hay alertas activas</span>
                </div>
            `;
            return;
        }

        alertsList.innerHTML = this.alerts.map(alert => `
            <div class="alert-item ${alert.level}" data-alert-id="${alert.id}">
                <div class="alert-icon">
                    <i class="fas ${this.getAlertIcon(alert.level)}"></i>
                </div>
                <div class="alert-content">
                    <div class="alert-message">${alert.message}</div>
                    <div class="alert-time">${alert.timestamp}</div>
                </div>
                <button class="alert-remove" onclick="realtimeMonitor.removeAlert(${alert.id})">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `).join('');
    }

    // Obtener icono de alerta
    getAlertIcon(level) {
        const icons = {
            'critical': 'fa-exclamation-circle',
            'warning': 'fa-exclamation-triangle',
            'info': 'fa-info-circle',
            'success': 'fa-check-circle',
            'error': 'fa-times-circle'
        };
        return icons[level] || 'fa-info-circle';
    }

    // Remover alerta
    removeAlert(alertId) {
        this.alerts = this.alerts.filter(alert => alert.id !== alertId);
        this.renderAlerts();
    }

    // Limpiar todas las alertas
    clearAlerts() {
        this.alerts = [];
        this.renderAlerts();
    }

    // Actualizar actividad reciente
    async updateActivity() {
        try {
            const response = await fetch('monitor_api.php?action=recent_activity', {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            const data = await response.json();
            
            if (data.success) {
                this.renderActivity(data.activities || []);
                document.getElementById('activity-count').textContent = `${data.activities.length} eventos`;
            }
        } catch (error) {
            console.error('Error actualizando actividad:', error);
        }
    }

    // Renderizar actividad
    renderActivity(activities) {
        const activityList = document.getElementById('activity-list');
        
        if (activities.length === 0) {
            activityList.innerHTML = `
                <div class="no-activity">
                    <i class="fas fa-clock"></i>
                    <span>No hay actividad reciente</span>
                </div>
            `;
            return;
        }

        activityList.innerHTML = activities.map(activity => `
            <div class="activity-item ${activity.type || 'info'}">
                <div class="activity-icon">
                    <i class="fas ${this.getActivityIcon(activity.action)}"></i>
                </div>
                <div class="activity-content">
                    <div class="activity-message">${activity.description || activity.action}</div>
                    <div class="activity-details">
                        <span class="activity-user">${activity.username || 'Sistema'}</span>
                        <span class="activity-time">${new Date(activity.timestamp).toLocaleString('es-ES')}</span>
                    </div>
                </div>
            </div>
        `).join('');
    }

    // Obtener icono de actividad
    getActivityIcon(action) {
        const icons = {
            'login_success': 'fa-sign-in-alt',
            'login_failed': 'fa-times-circle',
            'logout': 'fa-sign-out-alt',
            'user_created': 'fa-user-plus',
            'user_updated': 'fa-user-edit',
            'user_deleted': 'fa-user-minus',
            'backup_created': 'fa-database',
            'system_restart': 'fa-power-off',
            'config_changed': 'fa-cog',
            'relay_control': 'fa-toggle-on',
            'device_added': 'fa-plus-circle',
            'security_alert': 'fa-shield-alt'
        };
        return icons[action] || 'fa-info-circle';
    }

    // Inicializar gráficos
    initializeCharts() {
        // Solo inicializar si Chart.js está disponible
        if (typeof Chart === 'undefined') {
            console.warn('Chart.js no está disponible para gráficos');
            return;
        }

        this.createSystemChart();
        this.createSessionsChart();
    }

    // Crear gráfico del sistema
    createSystemChart() {
        const ctx = document.getElementById('system-chart');
        if (!ctx || this.charts.has('system')) return;

        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Uso de CPU %',
                    data: [],
                    borderColor: '#2199ea',
                    backgroundColor: 'rgba(33, 153, 234, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Uso de Memoria %',
                    data: [],
                    borderColor: '#28a745',
                    backgroundColor: 'rgba(40, 167, 69, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    }
                }
            }
        });

        this.charts.set('system', chart);
    }

    // Crear gráfico de sesiones
    createSessionsChart() {
        const ctx = document.getElementById('sessions-chart');
        if (!ctx || this.charts.has('sessions')) return;

        const chart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Usuarios Activos', 'Sesiones Inactivas'],
                datasets: [{
                    data: [0, 0],
                    backgroundColor: [
                        '#28a745',
                        '#6c757d'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        position: 'bottom'
                    }
                }
            }
        });

        this.charts.set('sessions', chart);
    }

    // Actualizar gráficos
    updateCharts() {
        // Implementar actualización de datos de gráficos
        console.log('📊 Actualizando gráficos...');
    }

    // Exportar datos de monitoreo
    exportMonitoringData() {
        const data = {
            timestamp: new Date().toISOString(),
            alerts: this.alerts,
            thresholds: this.thresholds,
            monitoring_duration: this.isActive ? 'active' : 'inactive'
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `skyn3t_monitoring_${Date.now()}.json`;
        a.click();
        
        URL.revokeObjectURL(url);
    }
}

// Instancia global del monitor
const realtimeMonitor = new RealTimeMonitor();

// Estilos CSS para el monitor
const monitorStyles = `
<style>
.monitor-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.9);
    z-index: 10000;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    backdrop-filter: blur(5px);
}

.monitor-container {
    background: rgba(55, 65, 79, 0.95);
    backdrop-filter: blur(20px);
    border: 2px solid rgba(33, 153, 234, 0.3);
    border-radius: 20px;
    width: 95vw;
    height: 90vh;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
}

.monitor-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px 30px;
    border-bottom: 1px solid rgba(33, 153, 234, 0.2);
    background: rgba(0, 0, 0, 0.2);
}

.monitor-title {
    color: #ffffff;
    font-size: 20px;
    font-weight: 600;
    margin: 0;
}

.monitor-controls {
    display: flex;
    align-items: center;
    gap: 15px;
}

.monitor-status {
    display: flex;
    align-items: center;
    gap: 8px;
    color: rgba(255, 255, 255, 0.8);
    font-size: 14px;
}

.status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #6c757d;
}

.status-dot.connected {
    background: #28a745;
    box-shadow: 0 0 10px rgba(40, 167, 69, 0.5);
    animation: pulse 2s infinite;
}

.status-dot.disconnected {
    background: #dc3545;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

.monitor-btn {
    background: rgba(33, 153, 234, 0.2);
    border: 1px solid rgba(33, 153, 234, 0.3);
    border-radius: 8px;
    color: #2199ea;
    padding: 8px 12px;
    cursor: pointer;
    transition: all 0.3s ease;
}

.monitor-btn:hover {
    background: rgba(33, 153, 234, 0.3);
}

.monitor-content {
    flex: 1;
    padding: 30px;
    display: flex;
    flex-direction: column;
    gap: 30px;
    overflow-y: auto;
}

.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
}

.metric-card {
    background: rgba(33, 153, 234, 0.1);
    border: 2px solid rgba(33, 153, 234, 0.2);
    border-radius: 15px;
    padding: 20px;
    text-align: center;
    transition: all 0.3s ease;
}

.metric-card.warning {
    border-color: rgba(255, 193, 7, 0.5);
    background: rgba(255, 193, 7, 0.1);
}

.metric-card.critical {
    border-color: rgba(220, 53, 69, 0.5);
    background: rgba(220, 53, 69, 0.1);
}

.metric-header {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    color: rgba(255, 255, 255, 0.8);
    font-size: 14px;
    margin-bottom: 10px;
}

.metric-value {
    color: #2199ea;
    font-size: 24px;
    font-weight: 700;
    margin-bottom: 5px;
}

.metric-card.warning .metric-value {
    color: #ffc107;
}

.metric-card.critical .metric-value {
    color: #dc3545;
}

.metric-label {
    color: rgba(255, 255, 255, 0.6);
    font-size: 12px;
}

.alerts-panel, .activity-panel, .charts-panel {
    background: rgba(0, 0, 0, 0.2);
    border-radius: 15px;
    padding: 20px;
}

.panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding-bottom: 15px;
    border-bottom: 1px solid rgba(33, 153, 234, 0.2);
}

.panel-header h4 {
    color: #ffffff;
    margin: 0;
    font-size: 16px;
}

.alerts-list {
    max-height: 200px;
    overflow-y: auto;
}

.alert-item {
    display: flex;
    align-items: flex-start;
    gap: 15px;
    padding: 15px;
    margin-bottom: 10px;
    border-radius: 10px;
    border-left: 4px solid;
}

.alert-item.critical {
    background: rgba(220, 53, 69, 0.1);
    border-left-color: #dc3545;
}

.alert-item.warning {
    background: rgba(255, 193, 7, 0.1);
    border-left-color: #ffc107;
}

.alert-item.info {
    background: rgba(33, 153, 234, 0.1);
    border-left-color: #2199ea;
}

.alert-icon {
    color: currentColor;
    font-size: 16px;
    margin-top: 2px;
}

.alert-content {
    flex: 1;
}

.alert-message {
    color: #ffffff;
    font-size: 14px;
    margin-bottom: 5px;
}

.alert-time {
    color: rgba(255, 255, 255, 0.6);
    font-size: 12px;
}

.alert-remove {
    background: none;
    border: none;
    color: rgba(255, 255, 255, 0.5);
    cursor: pointer;
    padding: 5px;
    transition: color 0.3s ease;
}

.alert-remove:hover {
    color: #dc3545;
}

.no-alerts, .no-activity {
    text-align: center;
    padding: 40px;
    color: rgba(255, 255, 255, 0.6);
}

.charts-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-top: 20px;
}

.chart-container {
    background: rgba(0, 0, 0, 0.2);
    border-radius: 10px;
    padding: 20px;
    height: 250px;
}

.activity-list {
    max-height: 300px;
    overflow-y: auto;
}

.activity-item {
    display: flex;
    align-items: flex-start;
    gap: 15px;
    padding: 15px;
    margin-bottom: 10px;
    border-radius: 10px;
    background: rgba(33, 153, 234, 0.05);
    transition: background 0.3s ease;
}

.activity-item:hover {
    background: rgba(33, 153, 234, 0.1);
}

.activity-icon {
    color: #2199ea;
    font-size: 16px;
    margin-top: 2px;
}

.activity-content {
    flex: 1;
}

.activity-message {
    color: #ffffff;
    font-size: 14px;
    margin-bottom: 5px;
}

.activity-details {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.activity-user {
    color: #2199ea;
    font-size: 12px;
    font-weight: 600;
}

.activity-time {
    color: rgba(255, 255, 255, 0.6);
    font-size: 12px;
}

.chart-select {
    background: rgba(33, 153, 234, 0.1);
    border: 1px solid rgba(33, 153, 234, 0.3);
    border-radius: 8px;
    color: #ffffff;
    padding: 8px 12px;
    font-size: 14px;
}

.loading-activity {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    padding: 40px;
    color: rgba(255, 255, 255, 0.6);
}

.spinner.small {
    width: 20px;
    height: 20px;
    border-width: 2px;
}

@media (max-width: 768px) {
    .monitor-container {
        width: 100%;
        height: 100%;
        border-radius: 0;
    }
    
    .metrics-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    
    .charts-grid {
        grid-template-columns: 1fr;
    }
}
</style>
`;

// Inyectar estilos
document.head.insertAdjacentHTML('beforeend', monitorStyles);

// Función para mostrar el monitor desde la interfaz principal
function showRealtimeMonitor() {
    realtimeMonitor.showMonitor();
}