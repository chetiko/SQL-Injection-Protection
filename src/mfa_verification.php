<?php
require 'config.php'; // Incluye el archivo de configuración
require 'vendor/autoload.php'; // Carga las dependencias de Composer (incluye la librería para MFA)

// Verificar si el usuario está autenticado (asegúrate de que haya sesión activa)
session_start();
if (!isset($_SESSION['username'])) {
    die("Acceso denegado. Inicie sesión primero.");
}

// Verificar si el formulario ha sido enviado
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Obtener el código MFA proporcionado por el usuario
    $user_mfa_code = $_POST['mfa_code'];

    // Obtener el secreto MFA del usuario desde la base de datos
    $username = $_SESSION['username'];
    $conn = new mysqli($servername, $username, $password, $dbname);
    if ($conn->connect_error) {
        die("Conexión fallida: " . $conn->connect_error);
    }

    $stmt = $conn->prepare("SELECT mfa_secret FROM users WHERE username = ?");
    if ($stmt === false) {
        die("Error en la preparación de la consulta: " . $conn->error);
    }
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $mfa_secret = $row['mfa_secret'];

        // Verificar el código MFA utilizando la librería
        $totp = new \Sonata\GoogleAuthenticator\GoogleAuthenticator(); // Asegúrate de usar la librería correcta
        if ($totp->check($user_mfa_code, $mfa_secret)) {
            // Código MFA válido, autenticar al usuario
            echo "Autenticación MFA exitosa. Accediendo a la aplicación...";
            $_SESSION['mfa_authenticated'] = true;
            // Redirigir al usuario a la página principal o al dashboard
            header("Location: index.php");
            exit;
        } else {
            // Código MFA inválido
            echo "Código MFA inválido. Intenta de nuevo.";
        }
    } else {
        echo "Usuario no encontrado.";
    }

    $stmt->close();
    $conn->close();
} else {
    // Mostrar el formulario de verificación MFA
    ?>
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verificación MFA</title>
    </head>
    <body>
        <h1>Verificación de MFA</h1>
        <form action="mfa_verification.php" method="POST">
            <label for="mfa_code">Introduce el código MFA:</label>
            <input type="text" id="mfa_code" name="mfa_code" required>
            <button type="submit">Verificar</button>
        </form>
    </body>
    </html>
    <?php
}
?>

