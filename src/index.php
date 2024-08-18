<?php
// Incluir el archivo de configuración
require 'config.php';

// Verificar si se envió un formulario de inicio de sesión
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Incluir el archivo de funciones de MFA
    require 'mfa_verification.php';
    
    // Verificar el token CSRF
    if (!verify_csrf_token($_POST['csrf_token'])) {
        send_alert("Token CSRF no válido. IP: " . $_SERVER['REMOTE_ADDR']);
        die("Token CSRF no válido.");
    }

    // Validación y sanitización de entradas
    $user_input_username = sanitize_input($_POST['username']);
    $user_input_password = sanitize_input($_POST['password']);

    // Validar el formato del nombre de usuario
    if (!preg_match("/^[a-zA-Z0-9_]*$/", $user_input_username)) {
        log_activity("Intento de inicio de sesión con formato de usuario inválido: $user_input_username");
        die("Formato de nombre de usuario no válido.");
    }

    // Validar la contraseña
    if (!is_strong_password($user_input_password)) {
        die("La contraseña debe tener al menos 8 caracteres, incluyendo una letra mayúscula, una letra minúscula y un número.");
    }

    // Conectar a la base de datos
    $conn = new mysqli($servername, $username, $password, $dbname);
    if ($conn->connect_error) {
        error_log("Conexión fallida: " . $conn->connect_error);
        die("Ocurrió un error al conectar a la base de datos.");
    }

    // Usar consultas preparadas para prevenir SQL Injection
    $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username = ?");
    if ($stmt === false) {
        error_log("Error en la preparación de la consulta: " . $conn->error);
        die("Ocurrió un error en la aplicación.");
    }
    $stmt->bind_param("s", $user_input_username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        if (password_verify($user_input_password, $row['password'])) {
            // Autenticación exitosa
            echo "Bienvenido, " . htmlspecialchars($row["username"]);

            // Verificar y activar MFA
            if (isset($_POST['mfa_token'])) {
                $mfa_verified = verify_mfa_token($_POST['mfa_token']);
                if (!$mfa_verified) {
                    die("Código MFA no válido.");
                }
            }

            // Reiniciar el contador de intentos fallidos
            $_SESSION['login_attempts'] = 0;
            $ip_address = $_SERVER['REMOTE_ADDR'];
            $login_attempts_file = '/var/log/login_attempts.json';
            $attempts = json_decode(file_get_contents($login_attempts_file), true) ?? [];
            $attempts[$ip_address] = 0;  // Reiniciar intentos fallidos
            file_put_contents($login_attempts_file, json_encode($attempts));
        } else {
            // Contraseña incorrecta
            log_activity("Intento de inicio de sesión fallido para usuario: $user_input_username desde IP: " . $_SERVER['REMOTE_ADDR']);
            send_alert("Intento de inicio de sesión fallido para usuario: $user_input_username desde IP: " . $_SERVER['REMOTE_ADDR']);
            $_SESSION['login_attempts'] += 1;
            $ip_address = $_SERVER['REMOTE_ADDR'];
            $login_attempts_file = '/var/log/login_attempts.json';
            $attempts = json_decode(file_get_contents($login_attempts_file), true) ?? [];
            $attempts[$ip_address] = ($attempts[$ip_address] ?? 0) + 1;  // Incrementar intentos fallidos
            file_put_contents($login_attempts_file, json_encode($attempts));
            echo "Usuario o contraseña incorrectos";
        }
    } else {
        // Usuario no encontrado
        log_activity("Intento de inicio de sesión con usuario no registrado: $user_input_username desde IP: " . $_SERVER['REMOTE_ADDR']);
        send_alert("Intento de inicio de sesión con usuario no registrado: $user_input_username desde IP: " . $_SERVER['REMOTE_ADDR']);
        $_SESSION['login_attempts'] += 1;
        $ip_address = $_SERVER['REMOTE_ADDR'];
        $login_attempts_file = '/var/log/login_attempts.json';
        $attempts = json_decode(file_get_contents($login_attempts_file), true) ?? [];
        $attempts[$ip_address] = ($attempts[$ip_address] ?? 0) + 1;  // Incrementar intentos fallidos
        file_put_contents($login_attempts_file, json_encode($attempts));
        echo "Usuario o contraseña incorrectos";
    }

    // Cerrar la conexión y la declaración
    $stmt->close();
    $conn->close();
} else {
    // Mostrar formulario de inicio de sesión
    $csrf_token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $csrf_token;
    ?>
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Inicio de Sesión</title>
    </head>
    <body>
        <h1>Inicio de Sesión</h1>
        <form action="index.php" method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
            <label for="username">Nombre de Usuario:</label>
            <input type="text" id="username" name="username" required>
            <br>
            <label for="password">Contraseña:</label>
            <input type="password" id="password" name="password" required>
            <br>
            <label for="mfa_token">Código MFA (si está habilitado):</label>
            <input type="text" id="mfa_token" name="mfa_token">
            <br>
            <button type="submit">Iniciar Sesión</button>
        </form>
    </body>
    </html>
    <?php
}
?>
