import unittest
from src.gestor_credenciales.gestor_credenciales import (
    GestorCredenciales, 
    ErrorPoliticaPassword, 
    ErrorAutenticacion,
    ErrorServicioNoEncontrado,
    ErrorCredencialExistente
)
# from hypothesis import given # No usado en tests funcionales directos
# from hypothesis.strategies import text

class TestFuncionalesGestorCredenciales(unittest.TestCase):
    def setUp(self):
        self.clave_maestra_valida = "claveMaestraSegura123!"
        self.gestor = GestorCredenciales(self.clave_maestra_valida)
        self.password_robusta = "PasswordValida123*"
        self.password_debil = "corta"

    def test_añadir_y_verificar_credencial_exitosa(self):
        servicio = "TestServicio"
        usuario = "TestUsuario"
        
        self.gestor.añadir_credencial(self.clave_maestra_valida, servicio, usuario, self.password_robusta)
        
        # Verificar que se añadió (indirectamente, verificando la contraseña)
        self.assertTrue(self.gestor.verificar_password(self.clave_maestra_valida, servicio, usuario, self.password_robusta))

    def test_añadir_credencial_con_password_debil_falla(self):
        with self.assertRaises(ErrorPoliticaPassword):
            self.gestor.añadir_credencial(self.clave_maestra_valida, "TestFail", "UserFail", self.password_debil)

    def test_añadir_credencial_duplicada_falla(self):
        servicio = "DuplicadoServ"
        usuario = "DuplicadoUser"
        self.gestor.añadir_credencial(self.clave_maestra_valida, servicio, usuario, self.password_robusta)
        with self.assertRaises(ErrorCredencialExistente):
            self.gestor.añadir_credencial(self.clave_maestra_valida, servicio, usuario, "OtraPasswordVal1da*")

    def test_verificar_password_incorrecta_falla(self):
        servicio = "VerifServ"
        usuario = "VerifUser"
        self.gestor.añadir_credencial(self.clave_maestra_valida, servicio, usuario, self.password_robusta)
        self.assertFalse(self.gestor.verificar_password(self.clave_maestra_valida, servicio, usuario, "PasswordIncorrecta1*"))

    def test_verificar_password_credencial_no_existente_falla(self):
        with self.assertRaises(ErrorServicioNoEncontrado):
            self.gestor.verificar_password(self.clave_maestra_valida, "NoExisteServ", "NoExisteUser", self.password_robusta)

    def test_listar_servicios(self):
        self.assertEqual(self.gestor.listar_servicios(self.clave_maestra_valida), []) # Lista vacía inicialmente
        
        self.gestor.añadir_credencial(self.clave_maestra_valida, "Servicio1", "userA", self.password_robusta)
        self.gestor.añadir_credencial(self.clave_maestra_valida, "Servicio2", "userB", self.password_robusta)
        # Añadir otra credencial para Servicio1 para asegurar que no se duplica en la lista de servicios
        self.gestor.añadir_credencial(self.clave_maestra_valida, "Servicio1", "userC", "PasswordValida234&")

        servicios_listados = self.gestor.listar_servicios(self.clave_maestra_valida)
        self.assertCountEqual(servicios_listados, ["Servicio1", "Servicio2"]) # Compara listas sin importar el orden

    def test_eliminar_credencial_exitosa(self):
        servicio = "ElimServ"
        usuario = "ElimUser"
        self.gestor.añadir_credencial(self.clave_maestra_valida, servicio, usuario, self.password_robusta)
        
        # Confirmar que existe antes de eliminar
        self.assertTrue(self.gestor.verificar_password(self.clave_maestra_valida, servicio, usuario, self.password_robusta))
        
        self.gestor.eliminar_credencial(self.clave_maestra_valida, servicio, usuario)
        
        # Confirmar que ya no existe
        with self.assertRaises(ErrorServicioNoEncontrado):
            self.gestor.verificar_password(self.clave_maestra_valida, servicio, usuario, self.password_robusta)
        
        # Verificar que el servicio se elimina de la lista si no quedan más usuarios
        servicios_listados = self.gestor.listar_servicios(self.clave_maestra_valida)
        self.assertNotIn(servicio, servicios_listados)

    def test_eliminar_credencial_no_existente_falla(self):
        with self.assertRaises(ErrorServicioNoEncontrado):
            self.gestor.eliminar_credencial(self.clave_maestra_valida, "NoExisteServ", "NoExisteUser")
            
    def test_operaciones_con_clave_maestra_incorrecta_fallan(self):
        clave_incorrecta = "incorrecta123"
        # Añadir una credencial con la clave correcta primero
        self.gestor.añadir_credencial(self.clave_maestra_valida, "ServicioTmp", "UserTmp", self.password_robusta)

        with self.assertRaises(ErrorAutenticacion):
            self.gestor.añadir_credencial(clave_incorrecta, "S", "U", self.password_robusta)
        with self.assertRaises(ErrorAutenticacion):
            self.gestor.verificar_password(clave_incorrecta, "ServicioTmp", "UserTmp", self.password_robusta)
        with self.assertRaises(ErrorAutenticacion):
            self.gestor.eliminar_credencial(clave_incorrecta, "ServicioTmp", "UserTmp")
        with self.assertRaises(ErrorAutenticacion):
            self.gestor.listar_servicios(clave_incorrecta)

    # Nuevos tests para la recuperación de credenciales
    def test_restablecer_y_verificar_nueva_clave_maestra(self):
        """Verifica que después de restablecer, la nueva clave maestra es la que se utiliza."""
        nueva_clave = "nuevaClaveMaestra123!"
        self.gestor.restablecer(nueva_clave)
        
        # Intentar añadir una credencial con la clave antigua debería fallar
        with self.assertRaises(ErrorAutenticacion):
            self.gestor.añadir_credencial(self.clave_maestra_valida, "Servicio", "Usuario", self.password_robusta)
        
        # Añadir una credencial con la nueva clave debería funcionar
        self.gestor.añadir_credencial(nueva_clave, "Servicio", "Usuario", self.password_robusta)
        
        # Verificar que se puede acceder con la nueva clave
        self.assertTrue(self.gestor.verificar_password(nueva_clave, "Servicio", "Usuario", self.password_robusta))

    def test_restablecer_elimina_credenciales(self):
        """Verifica que todas las credenciales se eliminan al restablecer el gestor."""
        # Añadir algunas credenciales
        self.gestor.añadir_credencial(self.clave_maestra_valida, "Servicio1", "Usuario1", self.password_robusta)
        self.gestor.añadir_credencial(self.clave_maestra_valida, "Servicio2", "Usuario2", self.password_robusta)
        
        # Restablecer con una nueva clave
        nueva_clave = "nuevaClave123!"
        self.gestor.restablecer(nueva_clave)
        
        # Intentar verificar las credenciales anteriores debería fallar
        with self.assertRaises(ErrorServicioNoEncontrado):
            self.gestor.verificar_password(nueva_clave, "Servicio1", "Usuario1", self.password_robusta)
        with self.assertRaises(ErrorServicioNoEncontrado):
            self.gestor.verificar_password(nueva_clave, "Servicio2", "Usuario2", self.password_robusta)
        
        # La lista de servicios debería estar vacía
        self.assertEqual(self.gestor.listar_servicios(nueva_clave), [])

    def test_añadir_credenciales_despues_de_restablecer(self):
        """Verifica que se pueden añadir y acceder a nuevas credenciales después de restablecer."""
        nueva_clave = "nuevaClaveMaestra123!"
        self.gestor.restablecer(nueva_clave)
        
        # Añadir una nueva credencial con la nueva clave
        self.gestor.añadir_credencial(nueva_clave, "NuevoServicio", "NuevoUsuario", self.password_robusta)
        
        # Verificar que se puede acceder correctamente
        self.assertTrue(self.gestor.verificar_password(nueva_clave, "NuevoServicio", "NuevoUsuario", self.password_robusta))
        
        # Intentar acceder con la clave antigua debería fallar
        with self.assertRaises(ErrorAutenticacion):
            self.gestor.verificar_password(self.clave_maestra_valida, "NuevoServicio", "NuevoUsuario", self.password_robusta)

if __name__ == "__main__":
    unittest.main()