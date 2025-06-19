<?php
error_reporting(E_ALL);
ini_set("display_errors", 1);

echo "<h1>Test Login Minimal</h1>";
echo "<p>PHP Version: " . PHP_VERSION . "</p>";

// Test 1: Include config
echo "<h2>Test 1: Include config.php</h2>";
if (file_exists("/var/www/html/includes/config.php")) {
    try {
        require_once "/var/www/html/includes/config.php";
        echo "<p style=\"color:green\">✓ config.php loaded</p>";
    } catch (Exception $e) {
        echo "<p style=\"color:red\">✗ Error: " . $e->getMessage() . "</p>";
    }
} else {
    echo "<p style=\"color:red\">✗ config.php not found</p>";
}

// Test 2: Include database
echo "<h2>Test 2: Include database.php</h2>";
if (file_exists("/var/www/html/includes/database.php")) {
    try {
        require_once "/var/www/html/includes/database.php";
        echo "<p style=\"color:green\">✓ database.php loaded</p>";
        
        // Test connection
        $db = Database::getInstance();
        if ($db->isConnected()) {
            echo "<p style=\"color:green\">✓ Database connected</p>";
        } else {
            echo "<p style=\"color:red\">✗ Database not connected</p>";
        }
    } catch (Exception $e) {
        echo "<p style=\"color:red\">✗ Error: " . $e->getMessage() . "</p>";
    }
} else {
    echo "<p style=\"color:red\">✗ database.php not found</p>";
}

// Test 3: Full init
echo "<h2>Test 3: Include init.php</h2>";
if (file_exists("/var/www/html/includes/init.php")) {
    try {
        ob_start();
        require_once "/var/www/html/includes/init.php";
        $output = ob_get_clean();
        echo "<p style=\"color:green\">✓ init.php loaded</p>";
        if ($output) {
            echo "<p>Output: " . htmlspecialchars($output) . "</p>";
        }
    } catch (Exception $e) {
        echo "<p style=\"color:red\">✗ Error: " . $e->getMessage() . "</p>";
    }
} else {
    echo "<p style=\"color:red\">✗ init.php not found</p>";
}
?>