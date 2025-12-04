## Contraseña para certificados de usuario
Las claves privadas de los usuarios se cifran con su contraseña de inicio de sesión por seguridad.
Para generar el certificado de un usuario, se descifra su clave privada usando esa contraseña.

## Certificados y claves de las autoridades de certificación
Las claves privadas de las autoridades de certificación AC1 y AC2 se cifran con contraseñas generadas
aleatoriamente con la librería secrets y dichas contraseñas se guardan en el keyring del sistema.

Por lo tanto, los certificados y claves de las autoridades de certificación que se encuentran en la
carpeta '(certificados_claves)' se envían para cumplir con lo indicado en el entregador de esta práctica, 

pero los certificados y las claves válidos se generarán al ejecutar el programa por primera vez en la PC.
