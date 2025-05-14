import hashlib
import bcrypt
from icontract import require, ensure, DBC

# Excepciones personalizadas
class ErrorPoliticaPassword(Exception):
    pass

class ErrorAutenticacion(Exception):
    pass

class ErrorServicioNoEncontrado(Exception):
    pass

class ErrorCredencialExistente(Exception):
    pass

class GestorCredenciales(DBC): # Heredar de DBC para activar icontracts
    def __init__(self, clave_maestra: str):
        """Inicializa el gestor con una clave maestra."""
        # Podríamos añadir una política para la clave_maestra aquí si fuera necesario
        self._clave_maestra_hashed = self._hash_clave(clave_maestra.encode('utf-8'))
        self._credenciales = {}  # Estructura: {servicio: {usuario: hashed_password}}

    def _hash_clave(self, clave: bytes) -> bytes:
        """Hashea una clave usando bcrypt."""
        return bcrypt.hashpw(clave, bcrypt.gensalt())
    
    def restablecer(self, nueva_clave_maestra: str) -> None:
        """Restablece el gestor de credenciales con una nueva clave maestra, eliminando todas las credenciales almacenadas."""
        self._clave_maestra_hashed = self._hash_clave(nueva_clave_maestra.encode('utf-8'))
        self._credenciales = {}
        
    def _verificar_clave(self, clave: bytes, clave_hashed: bytes) -> bool:
        """Verifica si una clave coincide con su hash."""
        try:
            return bcrypt.checkpw(clave, clave_hashed)
        except ValueError: # bcrypt puede lanzar ValueError si el hash es inválido
            return False

    def _autenticar(self, clave_maestra: str) -> None:
        """Verifica la clave maestra. Lanza ErrorAutenticacion si es incorrecta."""
        if not self._verificar_clave(clave_maestra.encode('utf-8'), self._clave_maestra_hashed):
            raise ErrorAutenticacion("Clave maestra incorrecta.")

    @staticmethod
    def _es_password_robusta(password: str) -> bool:
        """Verifica si una contraseña cumple con la política de robustez."""
        if len(password) < 12:
            return False
        if not any(c.isupper() for c in password):
            return False
        if not any(c.islower() for c in password):
            return False
        if not any(c.isdigit() for c in password):
            return False
        if not any(c in "!@#$%^&*" for c in password): # Simplificado a un conjunto de símbolos
            return False
        return True

    # icontracts para documentar y como segunda capa de validación
    @require(lambda servicio, usuario: bool(servicio and usuario), "Servicio y usuario no pueden estar vacíos.")
    @require(lambda servicio: all(c not in ";&|" for c in servicio), "Nombre de servicio inválido (posible inyección).")
    @require(lambda usuario: all(c not in ";&|" for c in usuario), "Nombre de usuario inválido (posible inyección).") # Añadido para usuario
    # Los icontracts de política de password se validarán explícitamente para lanzar ErrorPoliticaPassword
    # @require(lambda password: len(password) >= 12)
    # @require(lambda password: any(c.isupper() for c in password))
    # @require(lambda password: any(c.islower() for c in password))
    # @require(lambda password: any(c.isdigit() for c in password))
    # @require(lambda password: any(c in "!@#$%^&*" for c in password))
    @ensure(lambda self, servicio, usuario: (servicio in self._credenciales and usuario in self._credenciales[servicio]))
    def añadir_credencial(self, clave_maestra: str, servicio: str, usuario: str, password: str) -> None:
        """Añade una nueva credencial al gestor."""
        self._autenticar(clave_maestra)

        if not self._es_password_robusta(password):
            raise ErrorPoliticaPassword("La contraseña no cumple con la política de robustez.")

        if servicio not in self._credenciales:
            self._credenciales[servicio] = {}
        
        if usuario in self._credenciales[servicio]:
            raise ErrorCredencialExistente(f"Ya existe una credencial para el servicio '{servicio}' y usuario '{usuario}'.")

        hashed_password = self._hash_clave(password.encode('utf-8'))
        self._credenciales[servicio][usuario] = hashed_password

    @require(lambda servicio: bool(servicio), "Servicio no puede estar vacío.")
    @require(lambda usuario: bool(usuario), "Usuario no puede estar vacío.")
    @ensure(lambda result: isinstance(result, bool), "El resultado debe ser un booleano.")
    def verificar_password(self, clave_maestra: str, servicio: str, usuario: str, password_a_verificar: str) -> bool:
        """Verifica una contraseña almacenada."""
        self._autenticar(clave_maestra)

        if servicio not in self._credenciales or usuario not in self._credenciales[servicio]:
            raise ErrorServicioNoEncontrado(f"No se encontró credencial para el servicio '{servicio}' y usuario '{usuario}'.")
        
        hashed_password_almacenado = self._credenciales[servicio][usuario]
        return self._verificar_clave(password_a_verificar.encode('utf-8'), hashed_password_almacenado)

    @require(lambda servicio: bool(servicio), "Servicio no puede estar vacío.")
    @require(lambda usuario: bool(usuario), "Usuario no puede estar vacío.")
    @ensure(lambda self, servicio, usuario: not (servicio in self._credenciales and usuario in self._credenciales.get(servicio, {})))
    def eliminar_credencial(self, clave_maestra: str, servicio: str, usuario: str) -> None:
        """Elimina una credencial existente."""
        self._autenticar(clave_maestra)

        if servicio not in self._credenciales or usuario not in self._credenciales[servicio]:
            raise ErrorServicioNoEncontrado(f"No se encontró credencial para el servicio '{servicio}' y usuario '{usuario}' para eliminar.")
        
        del self._credenciales[servicio][usuario]
        if not self._credenciales[servicio]: # Si no quedan usuarios para este servicio
            del self._credenciales[servicio]

    @ensure(lambda result: isinstance(result, list))
    def listar_servicios(self, clave_maestra: str) -> list:
        """Lista todos los servicios almacenados."""
        self._autenticar(clave_maestra)
        return list(self._credenciales.keys())