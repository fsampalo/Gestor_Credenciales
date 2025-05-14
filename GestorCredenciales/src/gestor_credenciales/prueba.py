from gestor_credenciales import GestorCredenciales

# Crear el gestor con una clave maestra válida
gestor = GestorCredenciales("MiClaveSecreta123!")

# Añadir una credencial
gestor.añadir_credencial("MiClaveSecreta123!", "Gmail", "mi_usuario", "Contraseña123!")

# Verificar si funciona
print(gestor.verificar_password("MiClaveSecreta123!", "Gmail", "mi_usuario", "Contraseña123!"))  # Debería dar True
print(gestor.verificar_password("MiClaveSecreta123!", "Gmail", "mi_usuario", "ContraseñaErronea"))  # Debería dar False