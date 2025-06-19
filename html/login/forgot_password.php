<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Recuperar Contraseña | SKYN3T</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Arial', sans-serif;
            height: 100vh;
            overflow: hidden;
            background-color: #222831;
        }

        /* Fondo con imagen de la tierra */
        .background {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: url('/images/earth-bg.jpg') center/cover no-repeat, 
                        linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            background-size: cover;
            background-position: center;
            filter: blur(2px);
            transform: scale(1.1);
            transition: all 0.5s ease;
        }

        .background.blur-more {
            filter: blur(10px);
        }

        /* Logo flotante centrado */
        .floating-logo {
            position: fixed !important;
            top: 20px !important;
            left: 50% !important;
            transform: translateX(-50%) !important;
            z-index: 500 !important;
            pointer-events: auto !important;
        }
        
        .logo-img {
            max-width: 150px !important;
            height: auto !important;
            filter: drop-shadow(0 0 20px rgba(19,125,197,0.8)) !important;
            transition: all 0.3s ease !important;
            cursor: pointer !important;
            user-select: none !important;
        }
        
        .logo-img:hover {
            transform: scale(1.1) !important;
            filter: drop-shadow(0 0 30px rgba(19,125,197,1)) !important;
        }

        /* Botón volver flotante */
        .floating-back {
            position: fixed !important;
            top: 20px !important;
            left: 20px !important;
            z-index: 500 !important;
            background: rgba(55, 65, 79, 0.8) !important;
            backdrop-filter: blur(16px) !important;
            -webkit-backdrop-filter: blur(16px) !important;
            border: 2px solid rgba(33, 153, 234, 0.5) !important;
            color: #2199ea !important;
            width: 50px !important;
            height: 50px !important;
            border-radius: 50% !important;
            cursor: pointer !important;
            font-size: 1.3rem !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            transition: all 0.3s ease !important;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3) !important;
        }
        
        .floating-back:hover {
            background: rgba(33, 153, 234, 0.4) !important;
            transform: scale(1.1) !important;
        }

        /* Contenedor principal */
        .container {
            position: relative;
            width: 100%;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1;
            padding-top: 80px;
        }

        /* Caja de recuperación con efecto glassmorphism - mismo estilo que login */
        .recovery-box {
            background: rgba(55, 65, 79, 0.1);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 30px 40px 30px 40px;
            width: 400px;
            box-shadow: 0 8px 32px rgba(13, 15, 19, 0.3);
            border: 1px solid rgba(33, 153, 234, 0.2);
            transition: all 0.3s ease;
            animation: fadeIn 0.8s ease-out;
        }

        .recovery-box:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(13, 15, 19, 0.4);
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* Header con ícono */
        .recovery-header {
            text-align: center;
            margin-bottom: 25px;
            user-select: none;
        }

        .recovery-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #137DC5, #2199ea);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            color: white;
            font-size: 36px;
            box-shadow: 0 8px 25px rgba(33, 153, 234, 0.3);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% {
                box-shadow: 0 8px 25px rgba(33, 153, 234, 0.3);
            }
            50% {
                box-shadow: 0 8px 35px rgba(33, 153, 234, 0.5);
            }
        }

        .recovery-title {
            color: #ffffff;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 10px;
        }

        .recovery-subtitle {
            color: rgba(255, 255, 255, 0.8);
            font-size: 14px;
            line-height: 1.5;
        }

        /* Grupo de input - mismo estilo que login */
        .input-group {
            position: relative;
            margin-bottom: 25px;
        }

        .input-group input {
            width: 100%;
            padding: 15px 20px;
            background: rgba(15, 95, 150, 0.1);
            border: 2px solid rgba(33, 153, 234, 0.3);
            border-radius: 10px;
            color: #ffffff;
            font-size: 16px;
            outline: none;
            transition: all 0.3s ease;
        }

        .input-group input::placeholder {
            color: rgba(255, 255, 255, 0.6);
        }

        .input-group input:focus {
            background: rgba(33, 153, 234, 0.15);
            border-color: #137DC5;
            box-shadow: 0 0 15px rgba(19, 125, 197, 0.3);
        }

        .input-group label {
            position: absolute;
            top: -12px;
            left: 15px;
            background: #222831;
            padding: 0 8px;
            color: #2199ea;
            font-size: 14px;
            border-radius: 4px;
            transition: all 0.3s ease;
            user-select: none;
        }

        .input-group input:focus + label {
            color: #137DC5;
            text-shadow: 0 0 5px rgba(19, 125, 197, 0.5);
        }

        /* Botón de envío - mismo estilo que login */
        .recovery-btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #137DC5, #2199ea);
            border: none;
            border-radius: 10px;
            color: #ffffff;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
            position: relative;
            overflow: hidden;
            user-select: none;
            margin-bottom: 20px;
        }

        .recovery-btn:before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: rgba(255, 255, 255, 0.3);
            transition: left 0.5s ease;
            user-select: none;
        }

        .recovery-btn:hover:before {
            left: 100%;
        }

        .recovery-btn:hover {
            transform: scale(1.02);
            box-shadow: 0 5px 20px rgba(19, 125, 197, 0.4);
        }

        .recovery-btn:active {
            transform: scale(0.98);
        }

        .recovery-btn:disabled {
            background: rgba(255, 255, 255, 0.2);
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
            color: rgba(255, 255, 255, 0.5);
        }

        /* Enlaces de vuelta */
        .back-links {
            text-align: center;
            margin-top: 20px;
            color: #ffffff;
            font-size: 14px;
            user-select: none;
        }

        .back-links a {
            color: #2199ea;
            text-decoration: none;
            font-weight: 600;
            transition: color 0.3s ease;
            user-select: none;
        }

        .back-links a:hover {
            color: #0f5f96;
        }

        /* Footer - mismo estilo que login */
        .footer {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: rgba(15, 23, 42, 0.9);
            backdrop-filter: blur(10px);
            border-top: 1px solid rgba(33, 153, 234, 0.3);
            padding: 15px;
            text-align: center;
            z-index: 100;
        }

        .footer-text {
            color: #2199ea;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 2px;
            font-weight: 500;
            opacity: 0.8;
            transition: all 0.3s ease;
            position: relative;
            display: inline-block;
            cursor: pointer;
            user-select: none;
        }

        .footer-text:before {
            content: '◆';
            position: absolute;
            left: -20px;
            color: #137DC5;
            animation: footerPulse 2s infinite;
            user-select: none;
        }

        .footer-text:after {
            content: '◆';
            position: absolute;
            right: -20px;
            color: #137DC5;
            animation: footerPulse 2s infinite;
            user-select: none;
        }

        @keyframes footerPulse {
            0%, 100% {
                opacity: 0.3;
                transform: scale(0.8);
            }
            50% {
                opacity: 0.8;
                transform: scale(1.2);
            }
        }

        .footer:hover .footer-text {
            opacity: 1;
            color: #137DC5;
            text-shadow: 0 0 10px rgba(19, 125, 197, 0.5);
        }

        /* Mensaje de error/éxito - mismo estilo que login */
        .message {
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
            font-size: 14px;
            opacity: 0;
            transform: translateY(-10px);
            transition: all 0.3s ease;
        }

        .message.show {
            opacity: 1;
            transform: translateY(0);
        }

        .message.error {
            background: rgba(220, 53, 69, 0.2);
            color: #ff6b6b;
            border: 1px solid rgba(220, 53, 69, 0.3);
        }

        .message.success {
            background: rgba(19, 125, 197, 0.2);
            color: #137DC5;
            border: 1px solid rgba(19, 125, 197, 0.3);
        }

        .message.warning {
            background: rgba(255, 193, 7, 0.2);
            color: #ffc107;
            border: 1px solid rgba(255, 193, 7, 0.3);
        }

        /* Efecto de partículas - mismo que login */
        .particles {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            overflow: hidden;
        }

        .particle {
            position: absolute;
            background: rgba(19, 125, 197, 0.6);
            border-radius: 50%;
            pointer-events: none;
            animation: float 15s infinite linear;
        }

        @keyframes float {
            from {
                transform: translateY(100vh) rotate(0deg);
                opacity: 0;
            }
            10% {
                opacity: 1;
            }
            90% {
                opacity: 1;
            }
            to {
                transform: translateY(-100vh) rotate(720deg);
                opacity: 0;
            }
        }

        /* Animación shake */
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
            20%, 40%, 60%, 80% { transform: translateX(5px); }
        }

        .recovery-box.shake {
            animation: shake 0.5s ease-in-out;
        }

        /* Loading spinner */
        .loading-spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: #ffffff;
            animation: spin 1s ease-in-out infinite;
            margin-right: 8px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* Responsive */
        @media (max-width: 480px) {
            .recovery-box {
                width: 90%;
                padding: 25px 20px 20px 20px;
            }

            .floating-logo .logo-img {
                max-width: 120px !important;
            }

            .container {
                padding-top: 60px;
            }

            .footer-text {
                font-size: 10px;
            }

            .footer-text:before,
            .footer-text:after {
                display: none;
            }
        }

        /* Info adicional */
        .info-text {
            background: rgba(33, 153, 234, 0.1);
            border: 1px solid rgba(33, 153, 234, 0.3);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            color: rgba(255, 255, 255, 0.9);
            font-size: 13px;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <!-- Fondo con imagen de la tierra -->
    <div class="background" id="background"></div>
    
    <!-- Partículas flotantes -->
    <div class="particles" id="particles"></div>
    
    <!-- Logo flotante centrado -->
    <div class="floating-logo">
        <img src="/images/logo.png" alt="Logo SKYN3T" class="logo-img" onclick="goToLogin()">
    </div>
    
    <!-- Botón volver flotante -->
    <button class="floating-back" onclick="goBack()">
        ← 
    </button>
    
    <!-- Contenido principal -->
    <div class="container">
        <div class="recovery-box">
            <div class="recovery-header">
                <div class="recovery-icon">🔑</div>
                <h1 class="recovery-title">Recuperar Contraseña</h1>
                <p class="recovery-subtitle">Ingresa tu email para recibir las instrucciones de recuperación</p>
            </div>
            
            <div class="message" id="message"></div>
            
            <div class="info-text">
                <strong>📧 Instrucciones:</strong><br>
                • Introduce el email asociado a tu cuenta<br>
                • Recibirás un enlace de restablecimiento<br>
                • El enlace expira en 1 hora por seguridad
            </div>
            
            <form id="recoveryForm">
                <div class="input-group">
                    <input type="email" id="email" name="email" placeholder="tu.email@ejemplo.com" required maxlength="100">
                    <label for="email">Email</label>
                </div>
                
                <button type="submit" class="recovery-btn" id="recoveryBtn">Enviar Enlace</button>
            </form>
            
            <div class="back-links">
                ¿Recordaste tu contraseña? <a href="index_login.html">Iniciar sesión</a>
            </div>
        </div>
    </div>
    
    <!-- Footer -->
    <div class="footer">
        <span class="footer-text">SKYN3T - IT & NETWORK SOLUTIONS</span>
    </div>

    <script>
        let isSubmitting = false;

        // Crear partículas animadas - misma función que login
        function createParticles() {
            const particlesContainer = document.getElementById('particles');
            const particleCount = 20;

            for (let i = 0; i < particleCount; i++) {
                const particle = document.createElement('div');
                particle.className = 'particle';
                
                const size = Math.random() * 5 + 2;
                particle.style.width = size + 'px';
                particle.style.height = size + 'px';
                particle.style.left = Math.random() * 100 + '%';
                particle.style.animationDelay = Math.random() * 15 + 's';
                particle.style.animationDuration = (Math.random() * 10 + 15) + 's';
                
                particlesContainer.appendChild(particle);
            }
        }

        // Inicializar página
        document.addEventListener('DOMContentLoaded', function() {
            createParticles();
            initializeEventListeners();
            document.getElementById('email').focus();
        });

        // Inicializar event listeners
        function initializeEventListeners() {
            const recoveryForm = document.getElementById('recoveryForm');
            const emailInput = document.getElementById('email');
            const background = document.getElementById('background');
            const footerText = document.querySelector('.footer-text');

            // Manejar envío del formulario
            recoveryForm.addEventListener('submit', handleFormSubmit);

            // Efectos de enfoque
            emailInput.addEventListener('focus', function() {
                background.classList.add('blur-more');
            });

            emailInput.addEventListener('blur', function() {
                setTimeout(() => {
                    if (!document.activeElement.matches('input')) {
                        background.classList.remove('blur-more');
                    }
                }, 100);
            });

            // Limpiar mensajes al escribir
            emailInput.addEventListener('input', clearMessages);

            // Enter para enviar
            emailInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter' && this.value.trim()) {
                    e.preventDefault();
                    if (!isSubmitting) {
                        recoveryForm.dispatchEvent(new Event('submit'));
                    }
                }
            });

            // Efecto glitch en footer
            footerText.addEventListener('click', function() {
                this.style.animation = 'glitch 0.3s';
                setTimeout(() => {
                    this.style.animation = '';
                }, 300);
            });

            // Efecto hover en recovery box
            const recoveryBox = document.querySelector('.recovery-box');
            recoveryBox.addEventListener('mouseenter', function() {
                for (let i = 0; i < 3; i++) {
                    const particle = document.createElement('div');
                    particle.className = 'particle';
                    particle.style.width = '3px';
                    particle.style.height = '3px';
                    particle.style.left = Math.random() * 100 + '%';
                    particle.style.animationDuration = '5s';
                    document.getElementById('particles').appendChild(particle);
                    
                    setTimeout(() => {
                        particle.remove();
                    }, 5000);
                }
            });
        }

        // Manejar envío del formulario
        function handleFormSubmit(e) {
            e.preventDefault();
            
            if (isSubmitting) return;

            const email = document.getElementById('email').value.trim();
            
            // Validaciones
            if (!email) {
                showMessage('Por favor ingresa tu email', 'error');
                shakeBox();
                return;
            }

            if (!isValidEmail(email)) {
                showMessage('Por favor ingresa un email válido', 'error');
                shakeBox();
                return;
            }

            if (email.length > 100) {
                showMessage('Email demasiado largo', 'error');
                return;
            }

            // Iniciar proceso de recuperación
            startRecoveryProcess(email);
        }

        // Iniciar proceso de recuperación
        function startRecoveryProcess(email) {
            isSubmitting = true;
            const submitButton = document.getElementById('recoveryBtn');
            const background = document.getElementById('background');
            
            // Efectos visuales
            background.classList.add('blur-more');
            submitButton.disabled = true;
            submitButton.innerHTML = '<span class="loading-spinner"></span>ENVIANDO...';
            
            showMessage('Procesando solicitud...', 'success');
            
            // Crear FormData
            const formData = new FormData();
            formData.append('email', email);
            formData.append('action', 'reset_request');
            
            // Realizar petición
            fetch('forgot_password.php', {
                method: 'POST',
                body: formData,
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return response.json();
            })
            .then(data => {
                handleRecoveryResponse(data);
            })
            .catch(error => {
                console.error('Error:', error);
                handleRecoveryError(error);
            })
            .finally(() => {
                isSubmitting = false;
                resetRecoveryButton();
                setTimeout(() => {
                    document.getElementById('background').classList.remove('blur-more');
                }, 1000);
            });
        }

        // Manejar respuesta de recuperación
        function handleRecoveryResponse(data) {
            if (data.success) {
                showMessage('✅ ' + (data.message || 'Enlace de recuperación enviado. Revisa tu email.'), 'success');
                
                // Deshabilitar formulario temporalmente
                document.getElementById('email').disabled = true;
                document.getElementById('recoveryBtn').disabled = true;
                
                // Mostrar mensaje adicional
                setTimeout(() => {
                    showMessage('Si no recibes el email en unos minutos, revisa tu carpeta de spam.', 'warning');
                }, 3000);
                
                // Permitir nuevo intento después de 60 segundos
                setTimeout(() => {
                    document.getElementById('email').disabled = false;
                    document.getElementById('recoveryBtn').disabled = false;
                    showMessage('Puedes solicitar un nuevo enlace si es necesario.', 'success');
                }, 60000);
                
            } else {
                showMessage(data.message || 'Error al procesar la solicitud', 'error');
                shakeBox();
            }
        }

        // Manejar error de recuperación
        function handleRecoveryError(error) {
            if (error.message.includes('429')) {
                showMessage('Demasiadas solicitudes. Intenta más tarde.', 'warning');
            } else if (error.message.includes('404')) {
                showMessage('Email no encontrado en el sistema.', 'error');
            } else {
                showMessage('Error de conexión. Verifica tu internet.', 'error');
            }
            shakeBox();
        }

        // Resetear botón de recuperación
        function resetRecoveryButton() {
            const submitButton = document.getElementById('recoveryBtn');
            if (!submitButton.disabled) {
                submitButton.textContent = 'ENVIAR ENLACE';
            }
        }

        // Funciones auxiliares
        function showMessage(text, type) {
            const messageDiv = document.getElementById('message');
            messageDiv.textContent = text;
            messageDiv.className = `message ${type} show`;
            
            setTimeout(() => {
                messageDiv.classList.remove('show');
            }, 8000);
        }

        function clearMessages() {
            const messageDiv = document.getElementById('message');
            if (messageDiv.classList.contains('show')) {
                messageDiv.classList.remove('show');
            }
        }

        function shakeBox() {
            const recoveryBox = document.querySelector('.recovery-box');
            recoveryBox.classList.add('shake');
            setTimeout(() => {
                recoveryBox.classList.remove('shake');
            }, 500);
        }

        function isValidEmail(email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return emailRegex.test(email);
        }

        function goBack() {
            if (confirm('¿Estás seguro de que quieres volver al login?')) {
                window.location.href = 'index_login.html';
            }
        }

        function goToLogin() {
            window.location.href = 'index_login.html';
        }

        // Animación glitch para efectos
        function addGlitchEffect() {
            const elements = document.querySelectorAll('.recovery-title');
            elements.forEach(el => {
                el.style.animation = 'glitch 0.3s';
                setTimeout(() => {
                    el.style.animation = '';
                }, 300);
            });
        }
    </script>
</body>
</html>