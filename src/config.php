<?php
// Configuración de la base de datos
$servername = "localhost";
$username = "root";
$password = "password";
$dbname = "mi_base_de_datos";

// Configuración de sesión segura
ini_set('session.cookie_httponly', 1); // Hace que la cookie de sesión no sea accesible desde JavaScript
ini_set('session.cookie_secure', 1);   // Asegura que la cookie de sesión solo se envíe a través de HTTPS
ini_set('session.gc_maxlifetime', 3600); // Tiempo de vida máximo de la sesión en segundos
session_start(); // Inicia la sesión

// Configuración de seguridad de headers HTTP
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: SAMEORIGIN");
header("X-XSS-Protection: 1; mode=block");

// Configuración del archivo de intentos de inicio de sesión
$login_attempts_file = '/var/log/login_attempts.json';

// Clave secreta para la encriptación y verificación de tokens
define('SECRET_KEY', 'mi_clave_secreta');

// Configuración de la autenticación MFA
define('MFA_SECRET', 'mi_secreto_mfa'); // Clave secreta para MFA (puedes usar una librería como Google Authenticator)

// Funciones útiles
function log_activity($message) {
    $logfile = '/var/log/activity.log';
    file_put_contents($logfile, date('[Y-m-d H:i:s] ') . $message . PHP_EOL, FILE_APPEND);
}

function sanitize_input($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

function send_alert($message) {
    // Implementa la lógica para enviar alertas (por ejemplo, por correo electrónico)
    mail('admin@example.com', 'Alerta de Seguridad', $message);
}

// Función para generar un token CSRF
function generate_csrf_token() {
    return bin2hex(random_bytes(32));
}

// Función para verificar el token CSRF
function verify_csrf_token($token) {
    return isset($_SESSION['csrf_token']) && $token === $_SESSION['csrf_token'];
}

// Función para verificar el código MFA (ejemplo básico)
function verify_mfa_token($token) {
    // Implementa la lógica para verificar el token MFA, por ejemplo, usando Google Authenticator
    // Este es un ejemplo simple y deberías usar una librería como Google Authenticator para producción
    return $token === MFA_SECRET; // Reemplaza esta lógica con la verificación real de MFA
}
?>

