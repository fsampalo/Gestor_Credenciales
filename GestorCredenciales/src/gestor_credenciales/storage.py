# src/gestor_credenciales/storage.py

from abc import ABC, abstractmethod
import logging
from .exceptions import ErrorCredencialExistente

class StorageStrategy(ABC):
    """
    Clase Base Abstracta para estrategias de almacenamiento de credenciales.
    Define la interfaz para almacenar, recuperar y gestionar credenciales.
    """

    @abstractmethod
    def add_credential(self, service: str, user: str, hashed_password: bytes) -> None:
        """
        Añade una credencial al almacén.
        Args:
            service: El nombre del servicio.
            user: El nombre de usuario para el servicio.
            hashed_password: La contraseña hasheada para almacenar.
        Raises:
            ErrorCredencialExistente: Si la credencial (par servicio, usuario) ya existe.
        """
        pass

    @abstractmethod
    def get_credential(self, service: str, user: str) -> bytes | None:
        """
        Recupera la contraseña hasheada para un servicio y usuario dados.
        Args:
            service: El nombre del servicio.
            user: El nombre de usuario para el servicio.
        Returns:
            La contraseña hasheada como bytes si se encuentra, None en caso contrario.
        """
        pass

    @abstractmethod
    def remove_credential(self, service: str, user: str) -> bool:
        """
        Elimina una credencial del almacén.
        Args:
            service: El nombre del servicio.
            user: El nombre de usuario para el servicio.
        Returns:
            True si la credencial fue encontrada y eliminada, False en caso contrario.
        """
        pass

    @abstractmethod
    def list_services(self) -> list[str]:
        """
        Lista todos los servicios únicos para los cuales se almacenan credenciales.
        Returns:
            Una lista de nombres de servicios.
        """
        pass

    @abstractmethod
    def clear_all_credentials(self) -> None:
        """
        Elimina todas las credenciales del almacén.
        """
        pass

    @abstractmethod
    def credential_exists(self, service: str, user: str) -> bool:
        """
        Verifica si una credencial específica (par servicio, usuario) existe.
        Args:
            service: El nombre del servicio.
            user: El nombre de usuario para el servicio.
        Returns:
            True si la credencial existe, False en caso contrario.
        """
        pass


class InMemoryStorageStrategy(StorageStrategy):
    """
    Una implementación en memoria de StorageStrategy.
    Almacena las credenciales en un diccionario de Python.
    """
    def __init__(self):
        self._data_store: dict[str, dict[str, bytes]] = {}
        logging.info("InMemoryStorageStrategy initialized.")

    def add_credential(self, service: str, user: str, hashed_password: bytes) -> None:
        if service not in self._data_store:
            self._data_store[service] = {}
        
        if user in self._data_store[service]:
            logging.warning(f"InMemoryStorage: Attempt to add duplicate credential for {service} - {user}")
            raise ErrorCredencialExistente(f"Ya existe una credencial para el servicio '{service}' y usuario '{user}' en InMemoryStorage.")
        
        self._data_store[service][user] = hashed_password
        logging.info(f"InMemoryStorage: Credential added for {service} - {user}")

    def get_credential(self, service: str, user: str) -> bytes | None:
        credential = self._data_store.get(service, {}).get(user)
        if credential:
            logging.debug(f"InMemoryStorage: Credential retrieved for {service} - {user}")
        else:
            logging.debug(f"InMemoryStorage: Credential not found for {service} - {user}")
        return credential

    def remove_credential(self, service: str, user: str) -> bool:
        if service in self._data_store and user in self._data_store[service]:
            del self._data_store[service][user]
            if not self._data_store[service]:  # Si el servicio ya no tiene más usuarios
                del self._data_store[service]
            logging.info(f"InMemoryStorage: Credential removed for {service} - {user}")
            return True
        logging.warning(f"InMemoryStorage: Attempt to remove non-existent credential for {service} - {user}")
        return False

    def list_services(self) -> list[str]:
        services = list(self._data_store.keys())
        logging.debug(f"InMemoryStorage: Listed services: {services}")
        return services

    def clear_all_credentials(self) -> None:
        self._data_store = {}
        logging.info("InMemoryStorage: All credentials cleared.")

    def credential_exists(self, service: str, user: str) -> bool:
        exists = service in self._data_store and user in self._data_store[service]
        logging.debug(f"InMemoryStorage: Credential check for {service} - {user}: {'Exists' if exists else 'Does not exist'}")
        return exists