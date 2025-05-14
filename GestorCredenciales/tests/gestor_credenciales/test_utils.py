import unittest
from src.gestor_credenciales.utils import saludar

class TestUtils(unittest.TestCase):

    # Tests funcionales
    def test_saludar(self):
        # El PDF original usa assert, pero en unittest es self.assertEqual
        self.assertEqual(saludar("Antonio"), "Hola, Antonio!")
        self.assertEqual(saludar("Mundo"), "Hola, Mundo!")
        self.assertEqual(saludar(""), "Hola, !") # Testear caso borde

if __name__ == "__main__":
    unittest.main()