<?php
require 'config.php'; // Incluye el archivo de configuración
require 'vendor/autoload.php'; // Carga las dependencias de Composer (incluye la librería para MFA)

// Verificar si el usuario está autenticado (asegúrate de que haya sesión activa)
session_start();
if (!isset($_SESSION['username'])) {
    die("Acceso denegado. Inicie sesión primero.");
}

// Función para generar una URL de código QR
function get_qr_code_url($username, $secret) {
    $issuer = 'MiAplicacion'; // Nombre de tu aplicación
    $url = "otpauth://totp/$issuer:$username?secret=$secret&issuer=$issuer";
    return $url;
}

// Generar un nuevo secreto MFA
function generate_mfa_secret() {
    $secret = bin2hex(random_bytes(10)); // Genera un secreto aleatorio de 20 bytes (40 caracteres hexadecimales)
    return $secret;
}

// Verificar si se ha enviado el formulario para configurar MFA
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Obtener el usuario actual
    $username = $_SESSION['username'];

    // Generar un nuevo secreto y guardar en la base de datos
    $mfa_secret = generate_mfa_secret();
    
    // Conectar a la base de datos
    $conn = new mysqli($servername, $username, $password, $dbname);
    if ($conn->connect_error) {
        die("Conexión fallida: " . $conn->connect_error);
    }

    // Actualizar el secreto MFA en la base de datos
    $stmt = $conn->prepare("UPDATE users SET mfa_secret = ? WHERE username = ?");
    if ($stmt === false) {
        die("Error en la preparación de la consulta: " . $conn->error);
    }
    $stmt->bind_param("ss", $mfa_secret, $username);
    $stmt->execute();
    $stmt->close();
    $conn->close();

    // Generar la URL del código QR
    $qr_code_url = get_qr_code_url($username, $mfa_secret);
    ?>
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Configuración MFA</title>
    </head>
    <body>
        <h1>Configuración de MFA</h1>
        <p>Escanea el siguiente código QR con tu aplicación de autenticación:</p>
        <img src="https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=<?php echo urlencode($qr_code_url); ?>" alt="Código QR">
        <p>El secreto MFA es: <?php echo htmlspecialchars($mfa_secret); ?></p>
    </body>
    </html>
    <?php
} else {
    // Mostrar el formulario de configuración MFA
    ?>
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Configuración MFA</title>
    </head>
    <body>
        <h1>Configuración de MFA</h1>
        <form action="mfa_setup.php" method="POST">
            <button type="submit">Configurar MFA</button>
        </form>
    </body>
    </html>
    <?php
}
?>

