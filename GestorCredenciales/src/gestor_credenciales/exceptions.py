# Paso las excepciones de gestor_credenciales a un archivo aparte para que 
# no se mezclen con el código de la aplicación.

class ErrorPoliticaPassword(Exception):
    """Excepción que se lanza cuando una contraseña no cumple con los requisitos de la política de seguridad. Vamos, que no es lo suficientemente robusta."""
    pass

class ErrorAutenticacion(Exception):
    """Excepción que se lanza por fallos al intentar autenticarse, por ejemplo, si la clave maestra no es la correcta."""
    pass

class ErrorServicioNoEncontrado(Exception):
    """Excepción que se lanza cuando el servicio o la credencial de usuario que se busca no aparece por ningún lado."""
    pass

class ErrorCredencialExistente(Exception):
    """Excepción que se lanza cuando se intenta añadir una credencial que ya está registrada"""
    pass