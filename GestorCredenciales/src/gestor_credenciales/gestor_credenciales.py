# src/gestor_credenciales/gestor_credenciales.py

import bcrypt
import logging
import re
from icontract import require, ensure, DBC

from .exceptions import (
    ErrorPoliticaPassword,
    ErrorAutenticacion,
    ErrorServicioNoEncontrado,
    ErrorCredencialExistente
)
from .storage import StorageStrategy # Import new storage classes

# Configuración del logging seguro (si no está configurado globalmente)
logging.basicConfig(
    filename='gestor_credenciales.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Patrón para nombres válidos
VALID_NAME_PATTERN = r'^[a-zA-Z0-9_-]+$' # Allowing dots as well, common in service names/usernames

class GestorCredenciales(DBC):
    """
    Gestor de credenciales seguro que almacena y gestiona contraseñas.
    Utiliza una estrategia de almacenamiento inyectada para la persistencia de credenciales.
    """
    
    def __init__(self, clave_maestra: str, storage_strategy: StorageStrategy):
        """
        Inicializa el gestor con una clave maestra robusta y una estrategia de almacenamiento.
        
        Args:
            clave_maestra (str): Clave maestra para autenticar operaciones.
            storage_strategy (StorageStrategy): Estrategia para almacenar las credenciales.
        
        Raises:
            ErrorPoliticaPassword: Si la clave maestra no cumple con la política de robustez.
        """
        if not self._es_password_robusta(clave_maestra):
            logging.error("Error al inicializar Gestor: La clave maestra proporcionada es débil.")
            raise ErrorPoliticaPassword("La clave maestra no cumple con la política de robustez.")
        self._clave_maestra_hashed = self._hash_clave(clave_maestra.encode('utf-8'))
        self._storage = storage_strategy # Dependency Injection
        logging.info(f"Gestor de credenciales inicializado correctamente con {type(storage_strategy).__name__}.")

    def _hash_clave(self, clave: bytes) -> bytes:
        return bcrypt.hashpw(clave, bcrypt.gensalt())
    
    def _verificar_clave(self, clave: bytes, clave_hashed: bytes) -> bool:
        try:
            return bcrypt.checkpw(clave, clave_hashed)
        except ValueError: # Handles cases like malformed hash
            logging.warning("Error al verificar clave: hash malformado o incompatible.")
            return False

    def _autenticar(self, clave_maestra: str) -> None:
        if not self._verificar_clave(clave_maestra.encode('utf-8'), self._clave_maestra_hashed):
            logging.warning("Intento de autenticación fallido con clave maestra incorrecta.")
            raise ErrorAutenticacion("Clave maestra incorrecta.")
        logging.debug("Autenticación con clave maestra exitosa.")

    @staticmethod
    def _es_password_robusta(password: str) -> bool:
        if len(password) < 12:
            return False
        if not any(c.isupper() for c in password):
            return False
        if not any(c.islower() for c in password):
            return False
        if not any(c.isdigit() for c in password):
            return False
        # Consider common symbols for password policies
        if not any(c in "!@#$%^&*-_()" for c in password):
            return False
        return True

    def restablecer(self, nueva_clave_maestra: str) -> None:
        """
        Restablece el gestor con una nueva clave maestra y elimina todas las credenciales existentes.
        Args:
            nueva_clave_maestra (str): La nueva clave maestra a utilizar.
        Raises:
            ErrorPoliticaPassword: Si la nueva clave maestra no es robusta.
        """
        if not self._es_password_robusta(nueva_clave_maestra):
            logging.error("Error al restablecer: La nueva clave maestra proporcionada es débil.")
            raise ErrorPoliticaPassword("La nueva clave maestra no cumple con la política de robustez.")
        
        self._clave_maestra_hashed = self._hash_clave(nueva_clave_maestra.encode('utf-8'))
        self._storage.clear_all_credentials()
        logging.info("Gestor de credenciales restablecido: Nueva clave maestra configurada y todas las credenciales eliminadas.")

    @require(lambda servicio, usuario: bool(servicio and usuario), "Servicio y usuario no pueden estar vacíos.")
    @require(lambda servicio: re.match(VALID_NAME_PATTERN, servicio), "Nombre de servicio inválido (solo alfanuméricos, guiones o guiones bajos).")
    @require(lambda usuario: re.match(VALID_NAME_PATTERN, usuario), "Nombre de usuario inválido (solo alfanuméricos, guiones o guiones bajos).")
    @ensure(lambda self, servicio, usuario: self._storage.credential_exists(servicio, usuario), "La credencial no se añadió correctamente al almacenamiento.")
    def añadir_credencial(self, clave_maestra: str, servicio: str, usuario: str, password: str) -> None:
        self._autenticar(clave_maestra)
        
        if not self._es_password_robusta(password):
            logging.warning(f"Intento de añadir credencial con contraseña débil para servicio '{servicio}', usuario '{usuario}'.")
            raise ErrorPoliticaPassword("La contraseña no cumple con la política de robustez.")

        # ErrorCredencialExistente will be raised by the storage strategy if applicable
        hashed_password = self._hash_clave(password.encode('utf-8'))
        try:
            self._storage.add_credential(servicio, usuario, hashed_password)
            logging.info(f"Credencial añadida para servicio '{servicio}', usuario '{usuario}'.")
        except ErrorCredencialExistente:
            logging.warning(f"Intento de añadir credencial duplicada (detectado por storage) para servicio '{servicio}', usuario '{usuario}'.")
            raise # Re-raise the exception from storage

    @require(lambda servicio: bool(servicio), "Servicio no puede estar vacío.")
    @require(lambda usuario: bool(usuario), "Usuario no puede estar vacío.")
    @ensure(lambda result: isinstance(result, bool), "El resultado debe ser un booleano.")
    def verificar_password(self, clave_maestra: str, servicio: str, usuario: str, password_a_verificar: str) -> bool:
        self._autenticar(clave_maestra)

        hashed_password_almacenado = self._storage.get_credential(servicio, usuario)
        if hashed_password_almacenado is None:
            logging.warning(f"Intento de verificar credencial inexistente: servicio '{servicio}', usuario '{usuario}'.")
            raise ErrorServicioNoEncontrado(f"No se encontró credencial para el servicio '{servicio}' y usuario '{usuario}'.")
        
        result = self._verificar_clave(password_a_verificar.encode('utf-8'), hashed_password_almacenado)
        if result:
            logging.info(f"Verificación de contraseña exitosa para servicio '{servicio}', usuario '{usuario}'.")
        else:
            logging.warning(f"Verificación de contraseña fallida para servicio '{servicio}', usuario '{usuario}'.")
        return result

    @require(lambda servicio: bool(servicio), "Servicio no puede estar vacío.")
    @require(lambda usuario: bool(usuario), "Usuario no puede estar vacío.")
    @ensure(lambda self, servicio, usuario: not self._storage.credential_exists(servicio, usuario), "La credencial no se eliminó correctamente del almacenamiento.")
    def eliminar_credencial(self, clave_maestra: str, servicio: str, usuario: str) -> None:
        self._autenticar(clave_maestra)

        if not self._storage.remove_credential(servicio, usuario):
            logging.warning(f"Intento de eliminar credencial inexistente: servicio '{servicio}', usuario '{usuario}'.")
            raise ErrorServicioNoEncontrado(f"No se encontró credencial para el servicio '{servicio}' y usuario '{usuario}' para eliminar.")
        
        logging.info(f"Credencial eliminada para servicio '{servicio}', usuario '{usuario}'.")

    @ensure(lambda result: isinstance(result, list))
    def listar_servicios(self, clave_maestra: str) -> list[str]:
        self._autenticar(clave_maestra)
        servicios = self._storage.list_services()
        logging.info(f"Lista de servicios solicitada. {len(servicios)} servicio(s) encontrado(s).")
        return servicios