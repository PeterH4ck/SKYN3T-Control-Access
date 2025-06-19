<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$info = [
    'server' => [
        'ip' => $_SERVER['SERVER_ADDR'] ?? 'unknown',
        'hostname' => gethostname(),
        'software' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
        'php_version' => PHP_VERSION
    ],
    'client' => [
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ],
    'paths' => [
        'document_root' => $_SERVER['DOCUMENT_ROOT'],
        'script_filename' => $_SERVER['SCRIPT_FILENAME']
    ],
    'database' => false,
    'timestamp' => date('Y-m-d H:i:s')
];

// Test database connection
if (file_exists('includes/database.php')) {
    require_once 'includes/database.php';
    if (function_exists('getDBConnection')) {
        $pdo = getDBConnection();
        $info['database'] = ($pdo !== null);
    }
}

echo json_encode($info, JSON_PRETTY_PRINT);
?>
