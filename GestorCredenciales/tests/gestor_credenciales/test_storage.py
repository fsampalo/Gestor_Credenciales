# tests/test_storage.py

import unittest
from src.gestor_credenciales.storage import InMemoryStorageStrategy
from src.gestor_credenciales.exceptions import ErrorCredencialExistente

class TestInMemoryStorageStrategy(unittest.TestCase):
    def setUp(self):
        self.storage = InMemoryStorageStrategy()
        self.service1 = "service1"
        self.user1 = "user1"
        self.pass1_hash = b"hashed_pass1"
        self.service2 = "service2"
        self.user2 = "user2"
        self.pass2_hash = b"hashed_pass2"

    def test_add_and_get_credential(self):
        self.storage.add_credential(self.service1, self.user1, self.pass1_hash)
        retrieved_pass = self.storage.get_credential(self.service1, self.user1)
        self.assertEqual(retrieved_pass, self.pass1_hash)

    def test_get_non_existent_credential(self):
        self.assertIsNone(self.storage.get_credential("non_existent_service", "non_existent_user"))
        self.storage.add_credential(self.service1, self.user1, self.pass1_hash)
        self.assertIsNone(self.storage.get_credential(self.service1, "non_existent_user"))

    def test_add_duplicate_credential_raises_error(self):
        self.storage.add_credential(self.service1, self.user1, self.pass1_hash)
        with self.assertRaises(ErrorCredencialExistente):
            self.storage.add_credential(self.service1, self.user1, b"another_hash")

    def test_remove_credential(self):
        self.storage.add_credential(self.service1, self.user1, self.pass1_hash)
        self.assertTrue(self.storage.remove_credential(self.service1, self.user1))
        self.assertIsNone(self.storage.get_credential(self.service1, self.user1))
        self.assertFalse(self.storage.credential_exists(self.service1, self.user1))

    def test_remove_non_existent_credential(self):
        self.assertFalse(self.storage.remove_credential("non_existent_service", "non_existent_user"))

    def test_list_services(self):
        self.assertEqual(self.storage.list_services(), [])
        self.storage.add_credential(self.service1, self.user1, self.pass1_hash)
        self.storage.add_credential(self.service2, self.user2, self.pass2_hash)
        self.storage.add_credential(self.service1, "user1_another", b"another_hash_s1")
        
        services = self.storage.list_services()
        self.assertCountEqual(services, [self.service1, self.service2])

    def test_clear_all_credentials(self):
        self.storage.add_credential(self.service1, self.user1, self.pass1_hash)
        self.storage.add_credential(self.service2, self.user2, self.pass2_hash)
        self.storage.clear_all_credentials()
        self.assertEqual(self.storage.list_services(), [])
        self.assertIsNone(self.storage.get_credential(self.service1, self.user1))
        self.assertFalse(self.storage.credential_exists(self.service1, self.user1))

    def test_credential_exists(self):
        self.assertFalse(self.storage.credential_exists(self.service1, self.user1))
        self.storage.add_credential(self.service1, self.user1, self.pass1_hash)
        self.assertTrue(self.storage.credential_exists(self.service1, self.user1))
        self.assertFalse(self.storage.credential_exists(self.service1, "other_user"))
        self.assertFalse(self.storage.credential_exists("other_service", self.user1))

if __name__ == "__main__":
    unittest.main()