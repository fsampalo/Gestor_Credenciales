# test_seguridad_gestor_credenciales.py (tests/test_seguridad_gestor_credenciales.py - MODIFICADO)
import unittest
import logging
from src.gestor_credenciales import (
    GestorCredenciales, 
    ErrorPoliticaPassword, 
    ErrorAutenticacion,
    ErrorServicioNoEncontrado,
    ErrorCredencialExistente,
    InMemoryStorageStrategy # Importar estrategia
)
from hypothesis import given, strategies as st, settings
from icontract import ViolationError

class TestSeguridadGestorCredenciales(unittest.TestCase):
    def setUp(self):
        self.clave_maestra_valida = "claveMaestraSegura123!"
        self.storage = InMemoryStorageStrategy() # Crear instancia de almacenamiento
        self.gestor = GestorCredenciales(self.clave_maestra_valida, self.storage) # Inyectar almacenamiento
        self.password_robusta = "PasswordSegura123!"
        self.password_debil_longitud = "P1*"
        self.password_debil_no_mayus = "passwordvalida1*"
        self.password_debil_no_minus = "PASSWORDVALIDA1*"
        self.password_debil_no_num = "PasswordValida*"
        self.password_debil_no_simbolo = "PasswordValida1"

    def test_password_no_almacenado_en_plano(self):
        servicio = "GitHub"
        usuario = "user1"
        
        self.gestor.añadir_credencial(self.clave_maestra_valida, servicio, usuario, self.password_robusta)

        # El gestor hashea la contraseña y luego la entrega al almacenamiento. La recuperamos del almacenamiento.
        hashed_password_almacenado_bytes = self.gestor._storage.get_credential(servicio, usuario)
        
        self.assertIsNotNone(hashed_password_almacenado_bytes)
        self.assertIsInstance(hashed_password_almacenado_bytes, bytes)
        
        try:
            password_almacenado_str = hashed_password_almacenado_bytes.decode('utf-8')
            self.assertNotEqual(password_almacenado_str, self.password_robusta)
        except UnicodeDecodeError:
            pass 
        
        self.assertFalse(self.gestor._verificar_clave(hashed_password_almacenado_bytes, hashed_password_almacenado_bytes))


    def test_deteccion_inyeccion_servicio(self):
        # El PATTERN_NOMBRE_VALIDO original es ^[a-zA-Z0-9_-]+$
        # icontract lanzará ViolationError si el patrón no coincide
        casos_inyeccion = ["serv;icio", "servicio|mal", "servicio&", "servicio'--", "servicio.com"] # se añadió un punto, que ahora no está permitido
        for servicio_inyectado in casos_inyeccion:
            with self.subTest(servicio=servicio_inyectado):
                with self.assertRaises(ViolationError): 
                    self.gestor.añadir_credencial(
                        self.clave_maestra_valida,
                        servicio_inyectado,
                        "usuario_test",
                        self.password_robusta
                    )
    
    @settings(deadline=None, max_examples=50) 
    @given(st.text(min_size=1, max_size=20))
    def test_fuzz_politica_passwords_con_passwords_generadas(self, contrasena_generada):
        es_robusta_esperada = GestorCredenciales._es_password_robusta(contrasena_generada)
        # Reiniciar el almacenamiento para cada caso de fuzzing para evitar ErrorCredencialExistente entre ejecuciones de fuzzing
        # o asegurar un servicio/usuario único. setUp maneja un nuevo almacenamiento para cada *método* de prueba, no para cada caso @given.
        # Una forma sencilla es usar un nombre de servicio único para cada iteración @given
        # o crear una nueva instancia de gestor aquí. Usemos servicio/usuario único.

        current_storage = InMemoryStorageStrategy() # Almacenamiento nuevo para esta iteración de fuzzing
        current_gestor = GestorCredenciales(self.clave_maestra_valida, current_storage)

        servicio_unico = f"FuzzServ_{hash(contrasena_generada)}_{id(self)}" 
        usuario_unico = f"FuzzUser_{hash(contrasena_generada)}_{id(self)}"

        if not es_robusta_esperada:
            with self.assertRaises(ErrorPoliticaPassword, msg=f"Contraseña débil '{contrasena_generada}' debería haber fallado pero no lo hizo."):
                current_gestor.añadir_credencial(self.clave_maestra_valida, servicio_unico, usuario_unico, contrasena_generada)
        else:
            try:
                current_gestor.añadir_credencial(self.clave_maestra_valida, servicio_unico, usuario_unico, contrasena_generada)
                self.assertTrue(current_gestor.verificar_password(self.clave_maestra_valida, servicio_unico, usuario_unico, contrasena_generada))
            except ErrorPoliticaPassword:
                self.fail(f"Contraseña robusta '{contrasena_generada}' fue rechazada incorrectamente.")
            except ErrorCredencialExistente:
                # ErrorCredencialExistente no debería ocurrir con servicio/usuario único por llamada
                pass

    def test_politica_passwords_con_password_robusta_aceptada(self):
        try:
            self.gestor.añadir_credencial(self.clave_maestra_valida, "ServicioRobusto", "UserRobusto", self.password_robusta)
        except ErrorPoliticaPassword:
            self.fail("Una contraseña robusta fue rechazada.")
        self.assertTrue(self.gestor.verificar_password(self.clave_maestra_valida, "ServicioRobusto", "UserRobusto", self.password_robusta))

    def test_politica_passwords_con_passwords_debiles_especificas_rechazadas(self):
        passwords_debiles = [
            ("longitud", self.password_debil_longitud),
            ("no_mayuscula", self.password_debil_no_mayus),
            ("no_minuscula", self.password_debil_no_minus),
            ("no_numero", self.password_debil_no_num),
            ("no_simbolo", self.password_debil_no_simbolo),
            ("muy_corta", "a"),
            ("solo_numeros", "123456789012"),
            ("solo_letras_min", "abcdefghijkl"),
            ("solo_letras_may", "ABCDEFGHIJKL"),
        ]
        for i, (motivo, pwd_debil) in enumerate(passwords_debiles):
            with self.subTest(motivo=motivo, password=pwd_debil):
                with self.assertRaises(ErrorPoliticaPassword):
                    # Asegurar servicio/usuario único para cada subprueba para evitar problemas de estado de subpruebas anteriores
                    self.gestor.añadir_credencial(self.clave_maestra_valida, f"ServicioDebil_{motivo}_{i}", f"UserDebil_{motivo}_{i}", pwd_debil)

    def test_acceso_con_clave_maestra_erronea(self):
        clave_incorrecta = "claveErronea123!"
        self.gestor.añadir_credencial(self.clave_maestra_valida, "GitHub", "user1", self.password_robusta)

        with self.assertRaises(ErrorAutenticacion):
            self.gestor.verificar_password(clave_incorrecta, "GitHub", "user1", self.password_robusta)
        with self.assertRaises(ErrorAutenticacion):
            self.gestor.añadir_credencial(clave_incorrecta, "OtroServ", "user2", self.password_robusta)
        with self.assertRaises(ErrorAutenticacion):
            self.gestor.eliminar_credencial(clave_incorrecta, "GitHub", "user1")
        with self.assertRaises(ErrorAutenticacion):
            self.gestor.listar_servicios(clave_incorrecta)
    
    def test_seguridad_confidencialidad_clave_maestra_no_en_claro(self):
        self.assertIsInstance(self.gestor._clave_maestra_hashed, bytes)
        self.assertNotEqual(self.gestor._clave_maestra_hashed.decode('latin-1', errors='ignore'), self.clave_maestra_valida)
        self.assertFalse(self.gestor._verificar_clave(self.gestor._clave_maestra_hashed, self.gestor._clave_maestra_hashed))

    def test_seguridad_inyeccion_nombre_usuario(self):
        # El PATTERN_NOMBRE_VALIDO original es ^[a-zA-Z0-9_-]+$
        casos_inyeccion_usuario = ["user;", "user|mal", "user&", "user'--", "user.name"] # se añadió un punto
        for usuario_inyectado in casos_inyeccion_usuario:
            with self.subTest(usuario=usuario_inyectado):
                with self.assertRaises(ViolationError):
                    self.gestor.añadir_credencial(
                        self.clave_maestra_valida,
                        "ServicioParaUserIny",
                        usuario_inyectado,
                        self.password_robusta
                    )

    def test_seguridad_verificar_credencial_inexistente_usuario_diferente(self):
        servicio = "ServicioExistente"
        usuario_existente = "UsuarioExistente"
        self.gestor.añadir_credencial(self.clave_maestra_valida, servicio, usuario_existente, self.password_robusta)
        
        with self.assertRaises(ErrorServicioNoEncontrado):
            self.gestor.verificar_password(self.clave_maestra_valida, servicio, "UsuarioInexistente", self.password_robusta)

    def test_seguridad_eliminar_credencial_inexistente_servicio_diferente(self):
        with self.assertRaises(ErrorServicioNoEncontrado):
            self.gestor.eliminar_credencial(self.clave_maestra_valida, "ServicioInexistenteParaElim", "UsuarioCualquiera")

    def test_seguridad_listar_servicios_con_gestor_vacio_tras_eliminacion(self):
        s1 = "ServUnico1"
        u1 = "UserUnico1"
        self.gestor.añadir_credencial(self.clave_maestra_valida, s1, u1, self.password_robusta)
        self.assertCountEqual(self.gestor.listar_servicios(self.clave_maestra_valida), [s1])
        
        self.gestor.eliminar_credencial(self.clave_maestra_valida, s1, u1)
        self.assertEqual(self.gestor.listar_servicios(self.clave_maestra_valida), [])
        
    def test_seguridad_añadir_credencial_con_password_vacia_falla_politica(self):
        with self.assertRaises(ErrorPoliticaPassword):
            self.gestor.añadir_credencial(self.clave_maestra_valida, "ServicioPwdVacia", "UserPwdVacia", "")
            
    def test_seguridad_añadir_credencial_con_nombre_servicio_vacio_falla_icontract(self):
        with self.assertRaises(ViolationError):
            self.gestor.añadir_credencial(self.clave_maestra_valida, "", "UserValido", self.password_robusta)

    def test_seguridad_añadir_credencial_con_nombre_usuario_vacio_falla_icontract(self):
        with self.assertRaises(ViolationError):
            self.gestor.añadir_credencial(self.clave_maestra_valida, "ServicioValido", "", self.password_robusta)

if __name__ == "__main__":
    # logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    unittest.main()