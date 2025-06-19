<?php
/**
 * SKYN3T - Check Session Simple
 * Versión: 2.1.0 EMERGENCY FIX
 */

session_start();
header('Content-Type: application/json');

// Verificar si hay sesión activa
if (isset($_SESSION['user_id']) && isset($_SESSION['username'])) {
    echo json_encode([
        'authenticated' => true,
        'user' => [
            'id' => $_SESSION['user_id'],
            'username' => $_SESSION['username'],
            'role' => $_SESSION['role'] ?? 'User'
        ]
    ]);
} else {
    echo json_encode([
        'authenticated' => false
    ]);
}
?>
