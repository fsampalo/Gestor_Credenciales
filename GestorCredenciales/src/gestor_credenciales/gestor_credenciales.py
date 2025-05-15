import hashlib
import bcrypt
import logging
import re
from icontract import require, ensure, DBC

# Configuración del logging seguro
logging.basicConfig(
    filename='gestor_credenciales.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Excepciones personalizadas
class ErrorPoliticaPassword(Exception):
    pass

class ErrorAutenticacion(Exception):
    pass

class ErrorServicioNoEncontrado(Exception):
    pass

class ErrorCredencialExistente(Exception):
    pass

# Patrón para nombres válidos
VALID_NAME_PATTERN = r'^[a-zA-Z0-9_-]+$'

class GestorCredenciales(DBC):
    """Gestor de credenciales seguro que almacena y gestiona contraseñas."""
    
    def __init__(self, clave_maestra: str):
        """Inicializa el gestor con una clave maestra robusta.
        
        Args:
            clave_maestra (str): Clave maestra para autenticar operaciones.
        
        Raises:
            ErrorPoliticaPassword: Si la clave maestra no cumple con la política de robustez.
        """
        if not self._es_password_robusta(clave_maestra):
            raise ErrorPoliticaPassword("La clave maestra no cumple con la política de robustez.")
        self._clave_maestra_hashed = self._hash_clave(clave_maestra.encode('utf-8'))
        self._credenciales = {}  # Estructura: {servicio: {usuario: hashed_password}}
        logging.info("Gestor de credenciales inicializado correctamente.")

    def _hash_clave(self, clave: bytes) -> bytes:
        """Hashea una clave usando bcrypt para garantizar confidencialidad.
        
        Args:
            clave (bytes): Clave en bytes a hashear.
        
        Returns:
            bytes: Hash generado.
        """
        return bcrypt.hashpw(clave, bcrypt.gensalt())
    
    def restablecer(self, nueva_clave_maestra: str) -> None:
        if not self._es_password_robusta(nueva_clave_maestra):
            raise ErrorPoliticaPassword("La clave maestra no cumple con la política de robustez.")
        self._clave_maestra_hashed = self._hash_clave(nueva_clave_maestra.encode('utf-8'))
        self._credenciales = {}
        
    def _verificar_clave(self, clave: bytes, clave_hashed: bytes) -> bool:
        """Verifica si una clave coincide con su hash.
        
        Args:
            clave (bytes): Clave a verificar.
            clave_hashed (bytes): Hash almacenado.
        
        Returns:
            bool: True si coincide, False si no.
        """
        try:
            return bcrypt.checkpw(clave, clave_hashed)
        except ValueError:
            return False

    def _autenticar(self, clave_maestra: str) -> None:
        """Verifica la clave maestra para garantizar autenticidad.
        
        Args:
            clave_maestra (str): Clave maestra proporcionada.
        
        Raises:
            ErrorAutenticacion: Si la clave maestra es incorrecta.
        """
        if not self._verificar_clave(clave_maestra.encode('utf-8'), self._clave_maestra_hashed):
            logging.warning("Intento de autenticación fallido con clave maestra incorrecta.")
            raise ErrorAutenticacion("Clave maestra incorrecta.")

    @staticmethod
    def _es_password_robusta(password: str) -> bool:
        """Verifica si una contraseña cumple con la política de robustez.
        
        Args:
            password (str): Contraseña a validar.
        
        Returns:
            bool: True si es robusta, False si no.
        """
        if len(password) < 12:
            return False
        if not any(c.isupper() for c in password):
            return False
        if not any(c.islower() for c in password):
            return False
        if not any(c.isdigit() for c in password):
            return False
        if not any(c in "!@#$%^&*" for c in password):
            return False
        return True

    @require(lambda servicio, usuario: bool(servicio and usuario), "Servicio y usuario no pueden estar vacíos.")
    @require(lambda servicio: re.match(VALID_NAME_PATTERN, servicio), "Nombre de servicio inválido (solo alfanuméricos, guiones o guiones bajos).")
    @require(lambda usuario: re.match(VALID_NAME_PATTERN, usuario), "Nombre de usuario inválido (solo alfanuméricos, guiones o guiones bajos).")
    @ensure(lambda self, servicio, usuario: (servicio in self._credenciales and usuario in self._credenciales[servicio]))
    def añadir_credencial(self, clave_maestra: str, servicio: str, usuario: str, password: str) -> None:
        """Añade una nueva credencial al gestor.
        
        Args:
            clave_maestra (str): Clave maestra para autenticación.
            servicio (str): Nombre del servicio.
            usuario (str): Nombre del usuario.
            password (str): Contraseña a almacenar.
        
        Raises:
            ErrorAutenticacion: Si la clave maestra es incorrecta.
            ErrorPoliticaPassword: Si la contraseña no es robusta.
            ErrorCredencialExistente: Si la credencial ya existe.
        """
        self._autenticar(clave_maestra)
        
        if not self._es_password_robusta(password):
            logging.warning(f"Intento de añadir credencial con contraseña débil para {servicio} - {usuario}")
            raise ErrorPoliticaPassword("La contraseña no cumple con la política de robustez.")

        if servicio not in self._credenciales:
            self._credenciales[servicio] = {}
        
        if usuario in self._credenciales[servicio]:
            logging.warning(f"Intento de añadir credencial duplicada para {servicio} - {usuario}")
            raise ErrorCredencialExistente(f"Ya existe una credencial para el servicio '{servicio}' y usuario '{usuario}'.")

        hashed_password = self._hash_clave(password.encode('utf-8'))
        self._credenciales[servicio][usuario] = hashed_password
        logging.info(f"Credencial añadida para {servicio} - {usuario}")

    @require(lambda servicio: bool(servicio), "Servicio no puede estar vacío.")
    @require(lambda usuario: bool(usuario), "Usuario no puede estar vacío.")
    @ensure(lambda result: isinstance(result, bool), "El resultado debe ser un booleano.")
    def verificar_password(self, clave_maestra: str, servicio: str, usuario: str, password_a_verificar: str) -> bool:
        """Verifica si una contraseña coincide con la almacenada.
        
        Args:
            clave_maestra (str): Clave maestra para autenticación.
            servicio (str): Nombre del servicio.
            usuario (str): Nombre del usuario.
            password_a_verificar (str): Contraseña a verificar.
        
        Returns:
            bool: True si coincide, False si no.
        
        Raises:
            ErrorAutenticacion: Si la clave maestra es incorrecta.
            ErrorServicioNoEncontrado: Si no existe la credencial.
        """
        self._autenticar(clave_maestra)

        if servicio not in self._credenciales or usuario not in self._credenciales[servicio]:
            logging.warning(f"Intento de verificar credencial inexistente: {servicio} - {usuario}")
            raise ErrorServicioNoEncontrado(f"No se encontró credencial para el servicio '{servicio}' y usuario '{usuario}'.")
        
        hashed_password_almacenado = self._credenciales[servicio][usuario]
        result = self._verificar_clave(password_a_verificar.encode('utf-8'), hashed_password_almacenado)
        logging.info(f"Verificación de contraseña para {servicio} - {usuario}: {'éxito' if result else 'fallo'}")
        return result

    @require(lambda servicio: bool(servicio), "Servicio no puede estar vacío.")
    @require(lambda usuario: bool(usuario), "Usuario no puede estar vacío.")
    @ensure(lambda self, servicio, usuario: not (servicio in self._credenciales and usuario in self._credenciales.get(servicio, {})))
    def eliminar_credencial(self, clave_maestra: str, servicio: str, usuario: str) -> None:
        """Elimina una credencial existente.
        
        Args:
            clave_maestra (str): Clave maestra para autenticación.
            servicio (str): Nombre del servicio.
            usuario (str): Nombre del usuario.
        
        Raises:
            ErrorAutenticacion: Si la clave maestra es incorrecta.
            ErrorServicioNoEncontrado: Si no existe la credencial.
        """
        self._autenticar(clave_maestra)

        if servicio not in self._credenciales or usuario not in self._credenciales[servicio]:
            logging.warning(f"Intento de eliminar credencial inexistente: {servicio} - {usuario}")
            raise ErrorServicioNoEncontrado(f"No se encontró credencial para el servicio '{servicio}' y usuario '{usuario}' para eliminar.")
        
        del self._credenciales[servicio][usuario]
        if not self._credenciales[servicio]:
            del self._credenciales[servicio]
        logging.info(f"Credencial eliminada para {servicio} - {usuario}")

    @ensure(lambda result: isinstance(result, list))
    def listar_servicios(self, clave_maestra: str) -> list:
        """Lista todos los servicios almacenados.
        
        Args:
            clave_maestra (str): Clave maestra para autenticación.
        
        Returns:
            list: Lista de servicios.
        
        Raises:
            ErrorAutenticacion: Si la clave maestra es incorrecta.
        """
        self._autenticar(clave_maestra)
        servicios = list(self._credenciales.keys())
        logging.info("Lista de servicios solicitada.")
        return servicios