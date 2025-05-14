import unittest
from src.gestor_credenciales.gestor_credenciales import GestorCredenciales, ErrorPoliticaPassword, ErrorAutenticacion, CredencialNoEncontrada
from hypothesis import given
from hypothesis.strategies import text

class TestFuncionalesGestorCredenciales(unittest.TestCase):
    def setUp(self):
        self.gestor = GestorCredenciales("claveMaestraSegura123!")

    # Tests funcionales
    def test_añadir_credencial(self):
        # Caso 1: Añadir credencial válida
        self.gestor.añadir_credencial("claveMaestraSegura123!", "GitHub", "user1", "PasswordSegura123!")
        password = self.gestor.obtener_password("claveMaestraSegura123!", "GitHub", "user1")
        self.assertEqual(password, "PasswordSegura123!")

        # Caso 2: Contraseña que no cumple la política (demasiado corta)
        with self.assertRaises(ErrorPoliticaPassword):
            self.gestor.añadir_credencial("claveMaestraSegura123!", "GitHub", "user2", "weak")

        # Caso 3: Múltiples usuarios para el mismo servicio
        self.gestor.añadir_credencial("claveMaestraSegura123!", "GitHub", "user2", "OtraPassword123!")
        password2 = self.gestor.obtener_password("claveMaestraSegura123!", "GitHub", "user2")
        self.assertEqual(password2, "OtraPassword123!")

        # Caso 4: Diferentes servicios
        self.gestor.añadir_credencial("claveMaestraSegura123!", "Twitter", "user1", "TwitterPass123!")
        password_twitter = self.gestor.obtener_password("claveMaestraSegura123!", "Twitter", "user1")
        self.assertEqual(password_twitter, "TwitterPass123!")

        # Caso 5: Sobrescribir credencial existente
        self.gestor.añadir_credencial("claveMaestraSegura123!", "GitHub", "user1", "NuevaPassword123!")
        password_actualizada = self.gestor.obtener_password("claveMaestraSegura123!", "GitHub", "user1")
        self.assertEqual(password_actualizada, "NuevaPassword123!")

    def test_recuperar_credencial(self):
        # Primero, añadir una credencial
        self.gestor.añadir_credencial("claveMaestraSegura123!", "GitHub", "user1", "PasswordSegura123!")

        # Caso 1: Recuperar con clave correcta
        password = self.gestor.obtener_password("claveMaestraSegura123!", "GitHub", "user1")
        self.assertEqual(password, "PasswordSegura123!")

        # Caso 2: Recuperar con clave incorrecta
        with self.assertRaises(ErrorAutenticacion):
            self.gestor.obtener_password("claveIncorrecta", "GitHub", "user1")

        # Caso 3: Recuperar credencial no existente
        with self.assertRaises(CredencialNoEncontrada):
            self.gestor.obtener_password("claveMaestraSegura123!", "ServicioInexistente", "user1")

    def test_listar_servicios(self):
        # Caso 1: Sin credenciales
        self.assertEqual(self.gestor.listar_servicios(), [])

        # Caso 2: Con credenciales
        self.gestor.añadir_credencial("claveMaestraSegura123!", "GitHub", "user1", "PasswordSegura123!")
        self.gestor.añadir_credencial("claveMaestraSegura123!", "Twitter", "user1", "TwitterPass123!")
        self.gestor.añadir_credencial("claveMaestraSegura123!", "GitHub", "user2", "OtraPassword123!")
        servicios = self.gestor.listar_servicios()
        self.assertEqual(sorted(servicios), ["GitHub", "Twitter"])

if __name__ == "__main__":
    unittest.main()