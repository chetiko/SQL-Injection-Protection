# SQL-Injection-Protection

## Descripción

Este proyecto es una solución PHP integral para la protección contra inyecciones SQL y la implementación de autenticación multifactor (MFA). Está diseñado para mejorar la seguridad de las aplicaciones web mediante las siguientes características:

- **Protección contra Inyecciones SQL**: Utiliza consultas preparadas y técnicas de validación de entrada para prevenir ataques de inyección SQL, asegurando que las entradas del usuario sean correctamente sanitizadas y validadas antes de ser procesadas por la base de datos.

- **Autenticación Multifactor (MFA)**: Implementa un sistema de autenticación multifactor para agregar una capa adicional de seguridad al proceso de inicio de sesión. Esto asegura que, además de la contraseña, se requiera un segundo factor de autenticación para acceder a la cuenta del usuario.

- **Validación de Entradas**: Incluye validaciones robustas para asegurar que las entradas del usuario cumplan con los formatos esperados, ayudando a prevenir ataques basados en entradas maliciosas.

- **Protección contra Ataques de Fuerza Bruta**: Implementa medidas para limitar los intentos de inicio de sesión fallidos, bloqueando temporalmente las direcciones IP después de varios intentos fallidos y enviando alertas sobre actividades sospechosas.

- **Manejo Seguro de Sesiones**: Configura sesiones PHP para ser seguras, estableciendo parámetros para asegurar las cookies de sesión y proteger contra ataques de secuestro de sesión.

- **Manejo de Errores y Registro de Actividades**: Utiliza Monolog para registrar actividades y errores importantes, facilitando la supervisión y la auditoría de la seguridad.

## Requisitos

- PHP 7.4 o superior
- Extensión MySQLi
- Librería `sonata/google-authenticator` para MFA
- Librería `monolog/monolog` para manejo de logs

## Instalación

1. **Clona el repositorio**:
   ```bash
   git clone https://github.com/chetiko/sql-injection-protection.git


2. Navega al directorio del proyecto:
    ```bash
    cd sql-injection-protection
    ```

3. Instala las dependencias de Composer:
    ```bash
    composer install
    ```

4. Configura el archivo `config.php` con tus credenciales de base de datos.

5. Crea la base de datos y las tablas necesarias.

## Uso

1. Configura la MFA desde `mfa_setup.php`.
2. Verifica el código MFA desde `mfa_verification.php`.
3. Inicia sesión: Usa el formulario de inicio de sesión proporcionado para autenticarte con MFA.
4. Administra el sistema: Utiliza las funcionalidades de protección contra inyecciones SQL y autenticación MFA a través de la interfaz de usuario.


## Contribuciones

Si deseas contribuir, por favor realiza un fork del proyecto y envía tus pull requests.

## Licencia

Este proyecto está licenciado bajo la [Licencia MIT](LICENSE).
