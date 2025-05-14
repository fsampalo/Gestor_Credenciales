from gestor_credenciales import GestorCredenciales, ErrorPoliticaPassword, ErrorAutenticacion, ErrorServicioNoEncontrado, ErrorCredencialExistente

# Crear el gestor con una clave maestra válida
gestor = GestorCredenciales("MiClaveSecreta123!")

# Añadir una credencial válida
gestor.añadir_credencial("MiClaveSecreta123!", "Gmail", "mi_usuario", "Contraseña123!")

# Verificar si funciona
print(gestor.verificar_password("MiClaveSecreta123!", "Gmail", "mi_usuario", "Contraseña123!"))  # Debería dar True
print(gestor.verificar_password("MiClaveSecreta123!", "Gmail", "mi_usuario", "ContraseñaErronea"))  # Debería dar False

# Casos que generan WARNING
try:
    # Intento de añadir una contraseña débil
    gestor.añadir_credencial("MiClaveSecreta123!", "Gmail", "otro_usuario", "123")  # Genera WARNING
except ErrorPoliticaPassword:
    print("Error: Contraseña débil detectada")

try:
    # Intento de añadir una credencial duplicada
    gestor.añadir_credencial("MiClaveSecreta123!", "Gmail", "mi_usuario", "OtraContraseña123!")  # Genera WARNING
except ErrorCredencialExistente:
    print("Error: Credencial duplicada detectada")

try:
    # Intento de verificar una credencial inexistente
    gestor.verificar_password("MiClaveSecreta123!", "Facebook", "no_existe", "AlgunaContraseña")  # Genera WARNING
except ErrorServicioNoEncontrado:
    print("Error: Credencial no encontrada")

try:
    # Intento de eliminar una credencial inexistente
    gestor.eliminar_credencial("MiClaveSecreta123!", "Gmail", "no_existe")  # Genera WARNING
except ErrorServicioNoEncontrado:
    print("Error: Credencial no encontrada para eliminar")

try:
    # Intento de autenticación con clave maestra incorrecta
    gestor.añadir_credencial("ClaveIncorrecta", "Gmail", "nuevo_usuario", "Contraseña123!")  # Genera WARNING
except ErrorAutenticacion:
    print("Error: Clave maestra incorrecta")