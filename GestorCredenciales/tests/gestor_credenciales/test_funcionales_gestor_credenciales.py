# test_seguridad_gestor_credenciales.py (tests/test_seguridad_gestor_credenciales.py - MODIFICADO)
import unittest
import logging
import bcrypt
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
        # No inicializamos self.gestor aquí para el test de inicialización con clave débil
        # self.gestor = GestorCredenciales(self.clave_maestra_valida, self.storage) 
        self.password_robusta = "PasswordSegura123!"
        self.password_debil_longitud = "P1*"
        self.password_debil_no_mayus = "passwordvalida1*"
        self.password_debil_no_minus = "PASSWORDVALIDA1*"
        self.password_debil_no_num = "PasswordValida*"
        self.password_debil_no_simbolo = "PasswordValida1"
        self.password_muy_debil = "debil"

        # Crear un gestor para los tests que lo necesiten ya inicializado
        self.gestor_valido = GestorCredenciales(self.clave_maestra_valida, self.storage)

    def test_inicializacion_con_clave_maestra_debil_falla(self):
        """Cubre: if not self._es_password_robusta(clave_maestra): en __init__"""
        with self.assertLogs(level='ERROR') as log:
            with self.assertRaises(ErrorPoliticaPassword):
                GestorCredenciales(self.password_muy_debil, self.storage)
        self.assertIn("Error al inicializar Gestor: La clave maestra proporcionada es débil.", log.output[0])

    

    def test_restablecer_con_nueva_clave_maestra_debil_falla(self):
        """Cubre: if not self._es_password_robusta(nueva_clave_maestra): en restablecer"""
        # Usar el gestor válido para este test
        with self.assertLogs(level='ERROR') as log:
            with self.assertRaises(ErrorPoliticaPassword):
                self.gestor_valido.restablecer(self.password_muy_debil)
        self.assertIn("Error al restablecer: La nueva clave maestra proporcionada es débil.", log.output[0])

    def test_añadir_credencial_duplicada_logs_warning_y_re_raises(self):
        """
        Cubre el bloque except ErrorCredencialExistente en añadir_credencial:
            logging.warning(...)
            raise
        """
        servicio = "ServicioDuplicadoLog"
        usuario = "UsuarioDuplicadoLog"

        # Añadir la credencial por primera vez
        self.gestor_valido.añadir_credencial(
            self.clave_maestra_valida, servicio, usuario, self.password_robusta
        )

        # Intentar añadirla de nuevo y verificar el log y la excepción
        with self.assertLogs(level='WARNING') as log_catcher:
            with self.assertRaises(ErrorCredencialExistente):
                self.gestor_valido.añadir_credencial(
                    self.clave_maestra_valida, servicio, usuario, "OtraPasswordValida123!"
                )
        
        # Verificar el mensaje de log específico
        expected_log_message = (
            f"Intento de añadir credencial duplicada (detectado por storage) "
            f"para servicio '{servicio}', usuario '{usuario}'."
        )
        self.assertTrue(
            any(expected_log_message in record.getMessage() for record in log_catcher.records),
            "No se encontró el mensaje de log esperado para credencial duplicada."
        )

    def test_verificar_password_fallida_logs_warning(self):
        """
        Cubre el bloque else en verificar_password:
            logging.warning(...)
        """
        servicio = "ServicioVerifFalloLog"
        usuario = "UsuarioVerifFalloLog"
        password_correcta = self.password_robusta
        password_incorrecta = "PasswordIncorrecta123*"

        # Añadir la credencial
        self.gestor_valido.añadir_credencial(
            self.clave_maestra_valida, servicio, usuario, password_correcta
        )

        # Intentar verificar con una contraseña incorrecta y verificar el log
        with self.assertLogs(level='WARNING') as log_catcher:
            resultado = self.gestor_valido.verificar_password(
                self.clave_maestra_valida, servicio, usuario, password_incorrecta
            )
        
        self.assertFalse(resultado) # La verificación debe fallar

        # Verificar el mensaje de log específico
        expected_log_message = (
            f"Verificación de contraseña fallida para servicio '{servicio}', usuario '{usuario}'."
        )
        self.assertTrue(
            any(expected_log_message in record.getMessage() for record in log_catcher.records),
            "No se encontró el mensaje de log esperado para verificación de contraseña fallida."
        )

    def test_password_no_almacenado_en_plano(self):
        servicio = "GitHub"
        usuario = "user1"
        
        self.gestor_valido.añadir_credencial(self.clave_maestra_valida, servicio, usuario, self.password_robusta)

        hashed_password_almacenado_bytes = self.gestor_valido._storage.get_credential(servicio, usuario)
        
        self.assertIsNotNone(hashed_password_almacenado_bytes)
        self.assertIsInstance(hashed_password_almacenado_bytes, bytes)
        
        try:
            password_almacenado_str = hashed_password_almacenado_bytes.decode('utf-8')
            self.assertNotEqual(password_almacenado_str, self.password_robusta)
        except UnicodeDecodeError:
            pass 
        
        self.assertFalse(self.gestor_valido._verificar_clave(hashed_password_almacenado_bytes, hashed_password_almacenado_bytes))


    def test_deteccion_inyeccion_servicio(self):
        casos_inyeccion = ["serv;icio", "servicio|mal", "servicio&", "servicio'--", "servicio.com"]
        for servicio_inyectado in casos_inyeccion:
            with self.subTest(servicio=servicio_inyectado):
                with self.assertRaises(ViolationError): 
                    self.gestor_valido.añadir_credencial(
                        self.clave_maestra_valida,
                        servicio_inyectado,
                        "usuario_test",
                        self.password_robusta
                    )
    
    @settings(deadline=None, max_examples=50) 
    @given(st.text(min_size=1, max_size=20))
    def test_fuzz_politica_passwords_con_passwords_generadas(self, contrasena_generada):
        es_robusta_esperada = GestorCredenciales._es_password_robusta(contrasena_generada)
        
        # Usar una nueva instancia de almacenamiento y gestor para cada iteración de fuzzing
        # para asegurar el aislamiento completo, especialmente si el test pudiera modificar el estado
        # de una manera no deseada para otras iteraciones.
        fuzz_storage = InMemoryStorageStrategy() 
        fuzz_gestor = GestorCredenciales(self.clave_maestra_valida, fuzz_storage)

        servicio_unico = f"FuzzServ_{hash(contrasena_generada)}_{id(self)}" 
        usuario_unico = f"FuzzUser_{hash(contrasena_generada)}_{id(self)}"

        if not es_robusta_esperada:
            with self.assertRaises(ErrorPoliticaPassword, msg=f"Contraseña débil '{contrasena_generada}' debería haber fallado pero no lo hizo."):
                fuzz_gestor.añadir_credencial(self.clave_maestra_valida, servicio_unico, usuario_unico, contrasena_generada)
        else:
            try:
                fuzz_gestor.añadir_credencial(self.clave_maestra_valida, servicio_unico, usuario_unico, contrasena_generada)
                self.assertTrue(fuzz_gestor.verificar_password(self.clave_maestra_valida, servicio_unico, usuario_unico, contrasena_generada))
            except ErrorPoliticaPassword:
                self.fail(f"Contraseña robusta '{contrasena_generada}' fue rechazada incorrectamente.")
            except ErrorCredencialExistente:
                pass

    def test_politica_passwords_con_password_robusta_aceptada(self):
        try:
            self.gestor_valido.añadir_credencial(self.clave_maestra_valida, "ServicioRobusto", "UserRobusto", self.password_robusta)
        except ErrorPoliticaPassword:
            self.fail("Una contraseña robusta fue rechazada.")
        self.assertTrue(self.gestor_valido.verificar_password(self.clave_maestra_valida, "ServicioRobusto", "UserRobusto", self.password_robusta))

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
                    self.gestor_valido.añadir_credencial(self.clave_maestra_valida, f"ServicioDebil_{motivo}_{i}", f"UserDebil_{motivo}_{i}", pwd_debil)

    def test_acceso_con_clave_maestra_erronea(self):
        clave_incorrecta = "claveErronea123!"
        self.gestor_valido.añadir_credencial(self.clave_maestra_valida, "GitHub", "user1", self.password_robusta)

        with self.assertRaises(ErrorAutenticacion):
            self.gestor_valido.verificar_password(clave_incorrecta, "GitHub", "user1", self.password_robusta)
        with self.assertRaises(ErrorAutenticacion):
            self.gestor_valido.añadir_credencial(clave_incorrecta, "OtroServ", "user2", self.password_robusta)
        with self.assertRaises(ErrorAutenticacion):
            self.gestor_valido.eliminar_credencial(clave_incorrecta, "GitHub", "user1")
        with self.assertRaises(ErrorAutenticacion):
            self.gestor_valido.listar_servicios(clave_incorrecta)
    
    def test_seguridad_confidencialidad_clave_maestra_no_en_claro(self):
        self.assertIsInstance(self.gestor_valido._clave_maestra_hashed, bytes)
        self.assertNotEqual(self.gestor_valido._clave_maestra_hashed.decode('latin-1', errors='ignore'), self.clave_maestra_valida)
        self.assertFalse(self.gestor_valido._verificar_clave(self.gestor_valido._clave_maestra_hashed, self.gestor_valido._clave_maestra_hashed))

    def test_seguridad_inyeccion_nombre_usuario(self):
        casos_inyeccion_usuario = ["user;", "user|mal", "user&", "user'--", "user.name"] 
        for usuario_inyectado in casos_inyeccion_usuario:
            with self.subTest(usuario=usuario_inyectado):
                with self.assertRaises(ViolationError):
                    self.gestor_valido.añadir_credencial(
                        self.clave_maestra_valida,
                        "ServicioParaUserIny",
                        usuario_inyectado,
                        self.password_robusta
                    )

    def test_seguridad_verificar_credencial_inexistente_usuario_diferente(self):
        servicio = "ServicioExistente"
        usuario_existente = "UsuarioExistente"
        self.gestor_valido.añadir_credencial(self.clave_maestra_valida, servicio, usuario_existente, self.password_robusta)
        
        with self.assertRaises(ErrorServicioNoEncontrado):
            self.gestor_valido.verificar_password(self.clave_maestra_valida, servicio, "UsuarioInexistente", self.password_robusta)

    def test_seguridad_eliminar_credencial_inexistente_servicio_diferente(self):
        with self.assertRaises(ErrorServicioNoEncontrado):
            self.gestor_valido.eliminar_credencial(self.clave_maestra_valida, "ServicioInexistenteParaElim", "UsuarioCualquiera")

    def test_seguridad_listar_servicios_con_gestor_vacio_tras_eliminacion(self):
        s1 = "ServUnico1"
        u1 = "UserUnico1"
        self.gestor_valido.añadir_credencial(self.clave_maestra_valida, s1, u1, self.password_robusta)
        self.assertCountEqual(self.gestor_valido.listar_servicios(self.clave_maestra_valida), [s1])
        
        self.gestor_valido.eliminar_credencial(self.clave_maestra_valida, s1, u1)
        self.assertEqual(self.gestor_valido.listar_servicios(self.clave_maestra_valida), [])
        
    def test_seguridad_añadir_credencial_con_password_vacia_falla_politica(self):
        with self.assertRaises(ErrorPoliticaPassword):
            self.gestor_valido.añadir_credencial(self.clave_maestra_valida, "ServicioPwdVacia", "UserPwdVacia", "")
            
    def test_seguridad_añadir_credencial_con_nombre_servicio_vacio_falla_icontract(self):
        with self.assertRaises(ViolationError):
            self.gestor_valido.añadir_credencial(self.clave_maestra_valida, "", "UserValido", self.password_robusta)

    def test_seguridad_añadir_credencial_con_nombre_usuario_vacio_falla_icontract(self):
        with self.assertRaises(ViolationError):
            self.gestor_valido.añadir_credencial(self.clave_maestra_valida, "ServicioValido", "", self.password_robusta)

if __name__ == "__main__":
    # Para ver los logs durante las pruebas, descomenta la siguiente línea:
    # logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    unittest.main()