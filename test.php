<?php

// Configuration should ideally be in a separate config file
function getDbConnection() {
    $db_host = 'localhost';
    $db_username = 'root';
    $db_password = 'root@1234';
    $db_name = 'arnicaTest';

    $conn = new mysqli($db_host, $db_username, $db_password, $db_name);
    
    if ($conn->connect_error) {
        error_log("Database connection failed: " . $conn->connect_error);
        throw new Exception("Authentication system temporarily unavailable");
    }
    
    return $conn;
}

function logAuthAttempt($username, $success) {
    error_log(sprintf(
        "Login attempt: username=%s, success=%s, ip=%s, time=%s",
        $username,
        $success ? "true" : "false",
        $_SERVER['REMOTE_ADDR'],
        date('Y-m-d H:i:s')
    ));
}

function login($username, $password) {
    try {
        // Input validation
        if (!filter_var($username, FILTER_VALIDATE_EMAIL) && !preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
            throw new Exception("Invalid username format");
        }

        if (strlen($password) < 8) {
            throw new Exception("Invalid password format");
        }

        $conn = getDbConnection();

        // Prepare and bind - now selecting hashed password
        $stmt = $conn->prepare("SELECT password_hash FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        
        // Execute the statement
        $stmt->execute();
        $result = $stmt->get_result();

        // Check if user exists and verify password
        if ($result->num_rows === 1) {
            $row = $result->fetch_assoc();
            if (password_verify($password, $row['password_hash'])) {
                logAuthAttempt($username, true);
                echo "Welcome, " . htmlspecialchars($username) . "!";
                return;
            }
        }

        // Log failed attempt
        logAuthAttempt($username, false);
        echo "Invalid username or password.";

    } catch (Exception $e) {
        error_log("Login error: " . $e->getMessage());
        echo "An error occurred during authentication.";
    } finally {
        if (isset($stmt)) {
            $stmt->close();
        }
        if (isset($conn)) {
            $conn->close();
        }
    }
}

// Validate POST data exists
if (!isset($_POST['username']) || !isset($_POST['password'])) {
    echo "Missing required fields";
    exit;
}

$username = trim($_POST['username']);
$password = $_POST['password'];
login($username, $password);
?>
