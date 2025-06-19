// Utilidades localStorage
const KEY_MAIN = "onoff-btn-state";
const KEY_DIGITAL = "digital-switch-state";
const DEBUG_MODE = true; // Cambia a false para ocultar botón logs en prod

document.addEventListener('DOMContentLoaded', function () {
    const mainBtn = document.getElementById('main-btn');
    const mainIcon = document.getElementById('main-icon');
    const mainText = document.getElementById('main-text');
    const statusFeedback = document.getElementById('status-feedback');
    const digitalToggle = document.getElementById('digital-toggle');
    const digitalLabel = document.getElementById('digital-state-label');
    const alertBox = document.getElementById('alert-box');
    const alertMsg = document.getElementById('alert-msg');
    const alertClose = document.getElementById('alert-close');
    const debugBtn = document.getElementById('debug-log-btn');
    const modalLogs = document.getElementById('modal-logs');
    const logsOutput = document.getElementById('logs-output');
    const closeLogsBtn = document.getElementById('close-logs');
    const onoffContent = document.querySelector('.onoff-content'); // Para la animación

    let digitalEnabled = false; // Estado real del botón digital

    // --- Helpers ---
    function saveLocal(key, val) { try { localStorage.setItem(key, val);} catch {} }
    function loadLocal(key, defVal) { try { let v=localStorage.getItem(key); return (v===null?defVal:v);} catch{return defVal;} }
    function showAlert(msg, color) {
        alertBox.style.display = "flex";
        alertBox.style.background = color || "#f44336cc";
        alertMsg.textContent = msg;
    }
    function hideAlert() { alertBox.style.display = "none"; }
    
    function setMainBtnState(state, withAnimation = false) {
        mainBtn.classList.remove("on", "off");
        mainBtn.classList.add(state);
        
        // Aplicar animación popIn si se solicita
        if (withAnimation && onoffContent) {
            onoffContent.style.animation = 'none';
            // Forzar reflow para reiniciar la animación
            onoffContent.offsetHeight;
            onoffContent.style.animation = 'popIn 0.4s';
        }
        
        if (state === "on") {
            mainIcon.className = "fas fa-power-off";
            mainText.textContent = "ENCENDIDO";
            statusFeedback.textContent = "Sistema Activado";
        } else {
            mainIcon.className = "fas fa-power-off";
            mainText.textContent = "APAGADO";
            statusFeedback.textContent = "Sistema Desactivado";
        }
        saveLocal(KEY_MAIN, state);
    }
    
    function setDigitalLabel(state) {
        digitalLabel.textContent = state ? "TÁCTIL HABILITADO" : "TÁCTIL DESHABILITADO";
        digitalLabel.style.background = state ? "rgba(34,180,44,0.35)" : "rgba(200,0,0,0.25)";
        digitalLabel.style.color = "#fff";
        saveLocal(KEY_DIGITAL, state ? "on" : "off");
    }

    // --- Estado inicial ---
    // Digital: consulta backend
    fetch('/cgi-bin/rele-manager.py?action=status')
        .then(resp => resp.json())
        .then(data => {
            digitalEnabled = data.active;
            digitalToggle.checked = digitalEnabled;
            setDigitalLabel(digitalEnabled);
            if (DEBUG_MODE) debugBtn.style.display = "";
        })
        .catch(() => {
            digitalEnabled = false;
            digitalToggle.checked = false;
            setDigitalLabel(false);
            showAlert("Error al verificar estado del PANEL TÁCTIL.", "#e42");
        });

    // MainBtn: carga último estado (pero SOLO si digital habilitado)
    setTimeout(() => {
        let state = loadLocal(KEY_MAIN, "off");
        setMainBtnState(state, false); // Sin animación en la carga inicial
    }, 200);

    // --- Switch digital handler ---
    digitalToggle.addEventListener('change', function () {
        let desired = digitalToggle.checked;
        digitalToggle.disabled = true;
        let url = `/cgi-bin/rele-manager.py?action=${desired ? "start" : "stop"}`;
        fetch(url, { method: "POST" })
            .then(resp => resp.json())
            .then(data => {
                digitalEnabled = data.active;
                setDigitalLabel(digitalEnabled);
                showAlert(data.message || (digitalEnabled ? "Táctil Habilitado" : "Táctil Deshabilitado"), digitalEnabled ? "#28a745" : "#dc3545");
            })
            .catch(() => {
                digitalEnabled = false;
                digitalToggle.checked = false;
                setDigitalLabel(false);
                showAlert("Error al cambiar estado del Panel Táctil.", "#e42");
            })
            .finally(() => {
                digitalToggle.disabled = false;
            });
    });

    // --- Main button handler ---
    mainBtn.addEventListener('click', function () {
        if (!digitalEnabled) {
            showAlert("DEBES HABILITAR EL PANEL TÁCTIL!", "#c0392b");
            return;
        }

        let current = mainBtn.classList.contains("on") ? "on" : "off";
        let next = current === "on" ? "off" : "on";
        let url = `/cgi-bin/control-rele.py?action=${next}`;

        fetch(url, { method: "GET" })
            .then(resp => {
                if (!resp.ok) throw new Error("Error en la respuesta del servidor");
                return resp.json();
            })
            .then(data => {
                if (data.status === "success") {
                   setMainBtnState(next, true); // CON animación en el cambio de estado
                   // Mostrar notificación simplificada por 3 segundos
                   const statusMsg = next === "on" ? "ENCENDIDO" : "APAGADO";
                   showAlert(statusMsg, next === "on" ? "#28a745" : "#dc3545");
                   setTimeout(hideAlert, 4500); // Ocultar después de 4.5 segundos
                } else {
                   throw new Error(data.message || "Error al cambiar estado del relé");
                }
            })
            .catch(error => {
                showAlert(error.message || "Error al enviar comando al relé", "#e42");
                // Verificar estado actual del relé
                fetch('/cgi-bin/control-rele.py?action=status')
                    .then(resp => resp.json())
                    .then(data => {
                        if (data.state) {
                            setMainBtnState(data.state, false);
                        }
                    });
            });
    });

    // --- Alerta close ---
    alertClose.addEventListener('click', hideAlert);

    // --- Debug logs ---
    if (DEBUG_MODE) {
        debugBtn.addEventListener('click', function () {
            logsOutput.textContent = "Cargando logs...";
            modalLogs.style.display = "flex";
            fetch('/cgi-bin/rele-manager.py?action=log')
                .then(resp => resp.text())
                .then(log => logsOutput.textContent = log || "Sin logs.")
                .catch(() => logsOutput.textContent = "Error al obtener logs.");
        });
        closeLogsBtn.addEventListener('click', function () {
            modalLogs.style.display = "none";
        });
    }

// === BLOQUE RELOJ, FECHA Y TEMPERATURA AUTOMATIZADO ===

// Configuración: OpenWeatherMap API
const OPENWEATHERMAP_API_KEY = 'd59b0024bd0335251f73a022f49b1a86'; // <-- pon tu API KEY real aquí
const OPENWEATHERMAP_CITY = 'Santiago,CL'; // o "Las Condes,CL" si quieres algo más específico

// --- Hora y Fecha desde backend (Raspberry Pi) ---
async function updateClockFromBackend() {
    try {
        const res = await fetch('/cgi-bin/get-time.py');
        if (!res.ok) throw new Error('No se pudo obtener hora del sistema');
        const data = await res.json();

        // Actualizar elementos del DOM
        const clockDate = document.getElementById('clock-date');
        const clockTime = document.getElementById('clock-time');
        
        if (clockDate) clockDate.textContent = `${data.weekday}, ${data.date}`;
        if (clockTime) clockTime.textContent = data.time;
        
        console.log('[Clock] Hora actualizada:', data.time);
    } catch (e) {
        console.log('[Clock] Error obteniendo hora del backend:', e.message);
        // Fallback: usar hora local del navegador
        updateClockLocal();
    }
}

// --- Fallback: Hora local del navegador ---
function updateClockLocal() {
    try {
        const now = new Date();
        const options = { 
            weekday: 'long', 
            year: 'numeric', 
            month: 'long', 
            day: 'numeric' 
        };
        const dateStr = now.toLocaleDateString('es-ES', options);
        const timeStr = now.toLocaleTimeString('es-ES', { hour12: false });
        
        const clockDate = document.getElementById('clock-date');
        const clockTime = document.getElementById('clock-time');
        
        if (clockDate) clockDate.textContent = dateStr;
        if (clockTime) clockTime.textContent = timeStr;
        
        console.log('[Clock] Usando hora local del navegador:', timeStr);
    } catch (e) {
        console.log('[Clock] Error con hora local:', e.message);
    }
}

// --- Temperatura desde OpenWeatherMap ---
async function updateTemperatureOWM() {
    try {
        if (!OPENWEATHERMAP_API_KEY || OPENWEATHERMAP_API_KEY === 'd59b0024bd0335251f73a022f49b1a86') {
            throw new Error('API Key no configurada');
        }
        
        const url = `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(OPENWEATHERMAP_CITY)}&appid=${OPENWEATHERMAP_API_KEY}&units=metric&lang=es`;
        const res = await fetch(url);
        
        if (!res.ok) throw new Error(`Error HTTP: ${res.status}`);
        
        const data = await res.json();
        const temp = data.main && typeof data.main.temp === 'number' ? Math.round(data.main.temp) : '--';
        const description = data.weather && data.weather[0] ? data.weather[0].description : '';
        
        const clockTemp = document.getElementById('clock-temp');
        if (clockTemp) {
            clockTemp.textContent = `Temp: ${temp}°C`;
            clockTemp.title = description; // Tooltip con descripción del clima
        }
        
        console.log('[Weather] Temperatura actualizada:', `${temp}°C - ${description}`);
    } catch (e) {
        const clockTemp = document.getElementById('clock-temp');
        if (clockTemp) clockTemp.textContent = 'Temp: --°C';
        console.log('[Weather] Error obteniendo temperatura:', e.message);
    }
}

// --- Inicialización y intervalos automáticos ---
function initializeClockAndWeather() {
    console.log('[System] Inicializando reloj y clima...');
    
    // Primera carga inmediata
    updateClockFromBackend();
    updateTemperatureOWM();
    
    // Intervalos automáticos
    // Reloj: cada 30 segundos para mayor precisión
    setInterval(updateClockFromBackend, 1000);
    
    // Temperatura: cada 10 minutos (600000 ms) para respetar límites de API
    setInterval(updateTemperatureOWM, 600000);
    
    console.log('[System] Intervalos configurados - Reloj: 30s, Clima: 10min');
}

// --- Manejo de errores de red ---
window.addEventListener('online', function() {
    console.log('[Network] Conexión restaurada, actualizando datos...');
    updateClockFromBackend();
    updateTemperatureOWM();
});

window.addEventListener('offline', function() {
    console.log('[Network] Conexión perdida, usando fallbacks...');
});

// Inicializar todo
initializeClockAndWeather();

// --- Actualización manual si es necesario (para debugging) ---
window.manualUpdateClock = updateClockFromBackend;
window.manualUpdateWeather = updateTemperatureOWM;

});