from gestor_credenciales import GestorCredenciales, ErrorPoliticaPassword, ErrorAutenticacion, ErrorServicioNoEncontrado, ErrorCredencialExistente

# 1. Crear el gestor con una clave maestra válida
print("Ejecutando función: Crear GestorCredenciales (clave válida)...")
try:
    gestor = GestorCredenciales("MiClaveSecreta123!")
    print("Resultado: Gestor creado correctamente.")
except ErrorPoliticaPassword as e:
    print(f"Resultado: Error - {e} (esperado)")

# 2. Crear el gestor con una clave maestra débil
print("\nEjecutando función: Crear GestorCredenciales (clave débil)...")
try:
    GestorCredenciales("123")
    print("Resultado: Éxito (no esperado)")
except ErrorPoliticaPassword:
    print("Resultado: Error - La clave maestra no cumple con la política de robustez (esperado)")

# 3. Crear el gestor con una clave maestra vacía
print("\nEjecutando función: Crear GestorCredenciales (clave vacía)...")
try:
    GestorCredenciales("")
    print("Resultado: Éxito (no esperado)")
except ErrorPoliticaPassword:
    print("Resultado: Error - La clave maestra no cumple con la política de robustez (esperado)")

# 4. Crear el gestor con una clave maestra sin mayúsculas
print("\nEjecutando función: Crear GestorCredenciales (clave sin mayúsculas)...")
try:
    GestorCredenciales("miclavesecreta123!")
    print("Resultado: Éxito (no esperado)")
except ErrorPoliticaPassword:
    print("Resultado: Error - La clave maestra no cumple con la política de robustez (esperado)")

# 5. Crear el gestor con una clave maestra sin números
print("\nEjecutando función: Crear GestorCredenciales (clave sin números)...")
try:
    GestorCredenciales("MiClaveSecreta!")
    print("Resultado: Éxito (no esperado)")
except ErrorPoliticaPassword:
    print("Resultado: Error - La clave maestra no cumple con la política de robustez (esperado)")

# 6. Añadir una credencial válida
print("\nEjecutando función: añadir_credencial (caso válido)...")
try:
    gestor.añadir_credencial("MiClaveSecreta123!", "Gmail", "mi_usuario", "Contraseña123!")
    print("Resultado: Credencial añadida correctamente para Gmail - mi_usuario.")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 7. Añadir otra credencial válida (mismo servicio, usuario diferente)
print("\nEjecutando función: añadir_credencial (mismo servicio, usuario diferente)...")
try:
    gestor.añadir_credencial("MiClaveSecreta123!", "Gmail", "otro_usuario", "OtraContraseña123!")
    print("Resultado: Credencial añadida correctamente para Gmail - otro_usuario.")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 8. Añadir una credencial con contraseña débil
print("\nEjecutando función: añadir_credencial (contraseña débil)...")
try:
    gestor.añadir_credencial("MiClaveSecreta123!", "GitHub", "mi_usuario", "123")
    print("Resultado: Éxito (no esperado)")
except ErrorPoliticaPassword:
    print("Resultado: Error - Contraseña débil detectada (esperado)")

# 9. Añadir una credencial duplicada
print("\nEjecutando función: añadir_credencial (credencial duplicada)...")
try:
    gestor.añadir_credencial("MiClaveSecreta123!", "Gmail", "mi_usuario", "OtraContraseña123!")
    print("Resultado: Éxito (no esperado)")
except ErrorCredencialExistente:
    print("Resultado: Error - Credencial duplicada detectada (esperado)")

# 10. Añadir una credencial con clave maestra incorrecta
print("\nEjecutando función: añadir_credencial (clave maestra incorrecta)...")
try:
    gestor.añadir_credencial("ClaveIncorrecta", "GitHub", "mi_usuario", "Contraseña123!")
    print("Resultado: Éxito (no esperado)")
except ErrorAutenticacion:
    print("Resultado: Error - Clave maestra incorrecta (esperado)")

# 11. Añadir una credencial con servicio vacío
print("\nEjecutando función: añadir_credencial (servicio vacío)...")
try:
    gestor.añadir_credencial("MiClaveSecreta123!", "", "mi_usuario", "Contraseña123!")
    print("Resultado: Éxito (no esperado)")
except AssertionError:
    print("Resultado: Error - Servicio y usuario no pueden estar vacíos (esperado)")

# 12. Añadir una credencial con usuario vacío
print("\nEjecutando función: añadir_credencial (usuario vacío)...")
try:
    gestor.añadir_credencial("MiClaveSecreta123!", "GitHub", "", "Contraseña123!")
    print("Resultado: Éxito (no esperado)")
except AssertionError:
    print("Resultado: Error - Servicio y usuario no pueden estar vacíos (esperado)")

# 13. Añadir una credencial con inyección en servicio
print("\nEjecutando función: añadir_credencial (inyección en servicio)...")
try:
    gestor.añadir_credencial("MiClaveSecreta123!", "GitHub;drop", "mi_usuario", "Contraseña123!")
    print("Resultado: Éxito (no esperado)")
except AssertionError:
    print("Resultado: Error - Nombre de servicio inválido (posible inyección) (esperado)")

# 14. Añadir una credencial con inyección en usuario
print("\nEjecutando función: añadir_credencial (inyección en usuario)...")
try:
    gestor.añadir_credencial("MiClaveSecreta123!", "GitHub", "mi_usuario;drop", "Contraseña123!")
    print("Resultado: Éxito (no esperado)")
except AssertionError:
    print("Resultado: Error - Nombre de usuario inválido (posible inyección) (esperado)")

# 15. Añadir una credencial con caracteres especiales válidos
print("\nEjecutando función: añadir_credencial (caracteres especiales válidos)...")
try:
    gestor.añadir_credencial("MiClaveSecreta123!", "Git-Hub", "mi_usuario.123", "Contraseña123!")
    print("Resultado: Credencial añadida correctamente para Git-Hub - mi_usuario.123.")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 16. Añadir una credencial con cadenas largas
print("\nEjecutando función: añadir_credencial (cadenas largas)...")
try:
    servicio = "x" * 100
    usuario = "y" * 100
    contraseña = "Z123!abcde" + "f" * 90
    gestor.añadir_credencial("MiClaveSecreta123!", servicio, usuario, contraseña)
    print("Resultado: Credencial añadida correctamente para cadenas largas.")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 17. Añadir una credencial con contraseña con requisitos mínimos
print("\nEjecutando función: añadir_credencial (contraseña con requisitos mínimos)...")
try:
    gestor.añadir_credencial("MiClaveSecreta123!", "VulnDB", "mi_usuario", "Abcd123!efgh")
    print("Resultado: Credencial añadida correctamente con contraseña mínima.")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 18. Añadir una credencial con caracteres Unicode en contraseña
print("\nEjecutando función: añadir_credencial (contraseña con Unicode)...")
try:
    gestor.añadir_credencial("MiClaveSecreta123!", "VulnDB", "usuario_unicode", "Abcd123!éñøaA")
    print("Resultado: Credencial añadida correctamente con caracteres Unicode.")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 19. Verificar contraseña correcta
print("\nEjecutando función: verificar_password (contraseña correcta)...")
try:
    resultado = gestor.verificar_password("MiClaveSecreta123!", "Gmail", "mi_usuario", "Contraseña123!")
    print(f"Resultado: {resultado} (Esperado: True)")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 20. Verificar contraseña incorrecta
print("\nEjecutando función: verificar_password (contraseña incorrecta)...")
try:
    resultado = gestor.verificar_password("MiClaveSecreta123!", "Gmail", "mi_usuario", "ContraseñaErronea")
    print(f"Resultado: {resultado} (Esperado: False)")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 21. Verificar credencial inexistente
print("\nEjecutando función: verificar_password (credencial inexistente)...")
try:
    gestor.verificar_password("MiClaveSecreta123!", "Facebook", "no_existe", "AlgunaContraseña")
    print("Resultado: Éxito (no esperado)")
except ErrorServicioNoEncontrado:
    print("Resultado: Error - Credencial no encontrada (esperado)")

# 22. Verificar con clave maestra incorrecta
print("\nEjecutando función: verificar_password (clave maestra incorrecta)...")
try:
    gestor.verificar_password("ClaveIncorrecta", "Gmail", "mi_usuario", "Contraseña123!")
    print("Resultado: Éxito (no esperado)")
except ErrorAutenticacion:
    print("Resultado: Error - Clave maestra incorrecta (esperado)")

# 23. Verificar con servicio vacío
print("\nEjecutando función: verificar_password (servicio vacío)...")
try:
    gestor.verificar_password("MiClaveSecreta123!", "", "mi_usuario", "Contraseña123!")
    print("Resultado: Éxito (no esperado)")
except AssertionError:
    print("Resultado: Error - Servicio no puede estar vacío (esperado)")

# 24. Verificar con usuario vacío
print("\nEjecutando función: verificar_password (usuario vacío)...")
try:
    gestor.verificar_password("MiClaveSecreta123!", "Gmail", "", "Contraseña123!")
    print("Resultado: Éxito (no esperado)")
except AssertionError:
    print("Resultado: Error - Usuario no puede estar vacío (esperado)")

# 25. Verificar contraseña con Unicode
print("\nEjecutando función: verificar_password (contraseña con Unicode)...")
try:
    resultado = gestor.verificar_password("MiClaveSecreta123!", "VulnDB", "usuario_unicode", "Abcd123!éñøA")
    print(f"Resultado: {resultado} (Esperado: True)")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 26. Eliminar credencial válida
print("\nEjecutando función: eliminar_credencial (caso válido)...")
try:
    gestor.eliminar_credencial("MiClaveSecreta123!", "Gmail", "mi_usuario")
    print("Resultado: Credencial eliminada correctamente.")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 27. Eliminar credencial inexistente
print("\nEjecutando función: eliminar_credencial (credencial inexistente)...")
try:
    gestor.eliminar_credencial("MiClaveSecreta123!", "Gmail", "mi_usuario")
    print("Resultado: Éxito (no esperado)")
except ErrorServicioNoEncontrado:
    print("Resultado: Error - Credencial no encontrada para eliminar (esperado)")

# 28. Eliminar con clave maestra incorrecta
print("\nEjecutando función: eliminar_credencial (clave maestra incorrecta)...")
try:
    gestor.eliminar_credencial("ClaveIncorrecta", "Gmail", "otro_usuario")
    print("Resultado: Éxito (no esperado)")
except ErrorAutenticacion:
    print("Resultado: Error - Clave maestra incorrecta (esperado)")

# 29. Eliminar con servicio vacío
print("\nEjecutando función: eliminar_credencial (servicio vacío)...")
try:
    gestor.eliminar_credencial("MiClaveSecreta123!", "", "otro_usuario")
    print("Resultado: Éxito (no esperado)")
except AssertionError:
    print("Resultado: Error - Servicio no puede estar vacío (esperado)")

# 30. Eliminar con usuario vacío
print("\nEjecutando función: eliminar_credencial (usuario vacío)...")
try:
    gestor.eliminar_credencial("MiClaveSecreta123!", "Gmail", "")
    print("Resultado: Éxito (no esperado)")
except AssertionError:
    print("Resultado: Error - Usuario no puede estar vacío (esperado)")

# 31. Eliminar una credencial manteniendo otras
print("\nEjecutando función: eliminar_credencial (mantener otras credenciales)...")
try:
    gestor.eliminar_credencial("MiClaveSecreta123!", "Gmail", "otro_usuario")
    print("Resultado: Credencial eliminada correctamente, otras permanecen.")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 32. Listar servicios con credenciales
# Ensure each test starts with a clean state by resetting or creating a new instance

# 32. Listar servicios con credenciales
print("\nEjecutando función: listar_servicios (con credenciales)...")
try:
    gestor = GestorCredenciales("MiClaveSecreta123!")  # New instance for clean state
    gestor.añadir_credencial("MiClaveSecreta123!", "Git-Hub", "mi_usuario.123", "Password123!")
    gestor.añadir_credencial("MiClaveSecreta123!", "VulnDB", "usuario_unicode", "Abcd123!éñøA")
    servicios = gestor.listar_servicios("MiClaveSecreta123!")
    print(f"Resultado: Servicios actuales: {servicios} (Esperado: ['Git-Hub', 'VulnDB'])")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 33. Listar servicios tras eliminación
print("\nEjecutando función: listar_servicios (tras eliminación)...")
try:
    gestor = GestorCredenciales("MiClaveSecreta123!")  # New instance for clean state
    gestor.añadir_credencial("MiClaveSecreta123!", "Git-Hub", "mi_usuario.123", "Password123!")
    gestor.añadir_credencial("MiClaveSecreta123!", "VulnDB", "usuario_unicode", "Abcd123!éñøA")
    gestor.eliminar_credencial("MiClaveSecreta123!", "VulnDB", "usuario_unicode")
    servicios = gestor.listar_servicios("MiClaveSecreta123!")
    print(f"Resultado: Servicios actuales: {servicios} (Esperado: ['Git-Hub'])")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 34. Listar servicios con clave maestra incorrecta
print("\nEjecutando función: listar_servicios (clave maestra incorrecta)...")
try:
    gestor = GestorCredenciales("MiClaveSecreta123!")  # New instance
    gestor.listar_servicios("ClaveIncorrecta")
    print("Resultado: Éxito (no esperado)")
except ErrorAutenticacion:
    print("Resultado: Error - Clave maestra incorrecta (esperado)")

# 35. Listar servicios sin credenciales
print("\nEjecutando función: listar_servicios (sin credenciales)...")
try:
    gestor = GestorCredenciales("MiClaveSecreta123!")  # New instance for clean state
    servicios = gestor.listar_servicios("MiClaveSecreta123!")
    print(f"Resultado: Servicios actuales: {servicios} (Esperado: [])")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 36. Restablecer gestor con clave válida
print("\nEjecutando función: restablecer (clave válida)...")
try:
    gestor = GestorCredenciales("MiClaveSecreta123!")  # New instance
    gestor.añadir_credencial("MiClaveSecreta123!", "Gmail", "mi_usuario", "Contraseña123!")
    gestor.restablecer("NuevaClaveSecreta123!")
    servicios = gestor.listar_servicios("NuevaClaveSecreta123!")
    print(f"Resultado: Gestor restablecido, servicios: {servicios} (Esperado: [])")
except Exception as e:
    print(f"Resultado: Error - {e} (no esperado)")

# 37. Restablecer gestor con clave débil
print("\nEjecutando función: restablecer (clave débil)...")
try:
    gestor = GestorCredenciales("MiClaveSecreta123!")  # New instance
    gestor.restablecer("123")
    print("Resultado: Éxito (no esperado)")
except ErrorPoliticaPassword:
    print("Resultado: Error - La clave maestra no cumple con la política de robustez (esperado)")

# 38. Verificar clave maestra antigua tras restablecer
print("\nEjecutando función: listar_servicios (clave maestra antigua tras restablecer)...")
try:
    gestor = GestorCredenciales("MiClaveSecreta123!")  # New instance
    gestor.restablecer("NuevaClaveSecreta123!")
    gestor.listar_servicios("MiClaveSecreta123!")
    print("Resultado: Éxito (no esperado)")
except ErrorAutenticacion:
    print("Resultado: Error - Clave maestra incorrecta (esperado)")