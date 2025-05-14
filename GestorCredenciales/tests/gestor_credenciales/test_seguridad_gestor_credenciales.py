import unittest
from src.gestor_credenciales.gestor_credenciales import (
    GestorCredenciales, 
    ErrorPoliticaPassword, 
    ErrorAutenticacion,
    ErrorServicioNoEncontrado,
    ErrorCredencialExistente
)
from hypothesis import given, strategies as st, settings
from icontract import ViolationError # Para test de inyección con icontract

class TestSeguridadGestorCredenciales(unittest.TestCase):
    def setUp(self):
        self.clave_maestra_valida = "claveMaestraSegura123!"
        self.gestor = GestorCredenciales(self.clave_maestra_valida)
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

        # Verificar que el almacenamiento no contiene el password en plano
        # Accedemos al diccionario interno para la prueba (esto no se haría en producción)
        hashed_password_almacenado_bytes = self.gestor._credenciales[servicio][usuario]
        
        self.assertIsInstance(hashed_password_almacenado_bytes, bytes) # bcrypt devuelve bytes
        
        # Intentar decodificar y comparar (no debería ser igual)
        try:
            password_almacenado_str = hashed_password_almacenado_bytes.decode('utf-8')
            self.assertNotEqual(password_almacenado_str, self.password_robusta)
        except UnicodeDecodeError:
            # Esto es bueno, significa que no es simplemente la contraseña en UTF-8
            pass 
        
        # Otra forma de verificar es que bcrypt.checkpw falle si intentamos verificar el hash contra sí mismo como texto plano
        self.assertFalse(self.gestor._verificar_clave(hashed_password_almacenado_bytes, hashed_password_almacenado_bytes))


    def test_deteccion_inyeccion_servicio(self):
        casos_inyeccion = ["serv;icio", "servicio|mal", "servicio&", "servicio'--"]
        for servicio_inyectado in casos_inyeccion:
            with self.subTest(servicio=servicio_inyectado):
                with self.assertRaises(ViolationError): # icontract lanza ViolationError
                    self.gestor.añadir_credencial(
                        self.clave_maestra_valida,
                        servicio_inyectado,
                        "usuario_test",
                        self.password_robusta
                    )
    
    # Test con Fuzzing (usa Hypothesis)
    # Genera contraseñas de 1 a 20 caracteres.
    # settings(deadline=None) para evitar timeouts en CIs lentos con bcrypt
    @settings(deadline=None, max_examples=50) 
    @given(st.text(min_size=1, max_size=20))
    def test_fuzz_politica_passwords_con_passwords_generadas(self, contrasena_generada):
        """Prueba diferentes passwords. Si son débiles deben fallar, si son fuertes deben pasar."""
        es_robusta_esperada = GestorCredenciales._es_password_robusta(contrasena_generada)

        if not es_robusta_esperada:
            with self.assertRaises(ErrorPoliticaPassword, msg=f"Contraseña débil '{contrasena_generada}' debería haber fallado pero no lo hizo."):
                self.gestor.añadir_credencial(self.clave_maestra_valida, "FuzzServ", "FuzzUser", contrasena_generada)
        else:
            try:
                # Usar servicio y usuario únicos para cada intento de fuzzing para evitar ErrorCredencialExistente
                servicio_unico = f"FuzzServ_{hash(contrasena_generada)}" 
                usuario_unico = f"FuzzUser_{hash(contrasena_generada)}"
                self.gestor.añadir_credencial(self.clave_maestra_valida, servicio_unico, usuario_unico, contrasena_generada)
                # Si se añade, verificar que se puede usar (opcional, pero bueno para integridad)
                self.assertTrue(self.gestor.verificar_password(self.clave_maestra_valida, servicio_unico, usuario_unico, contrasena_generada))
            except ErrorPoliticaPassword:
                self.fail(f"Contraseña robusta '{contrasena_generada}' fue rechazada incorrectamente.")
            except ErrorCredencialExistente:
                 # Esto puede pasar si el hash de la contraseña genera colisión para servicio_unico/usuario_unico.
                 # Para este test, podemos ignorarlo o hacerlo más robusto. Por ahora, lo ignoramos.
                 pass


    def test_politica_passwords_con_password_robusta_aceptada(self):
        try:
            self.gestor.añadir_credencial(self.clave_maestra_valida, "ServicioRobusto", "UserRobusto", self.password_robusta)
        except ErrorPoliticaPassword:
            self.fail("Una contraseña robusta fue rechazada.")
        # Verificar que se añadió
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
        for motivo, pwd_debil in passwords_debiles:
            with self.subTest(motivo=motivo, password=pwd_debil):
                with self.assertRaises(ErrorPoliticaPassword):
                    self.gestor.añadir_credencial(self.clave_maestra_valida, f"ServicioDebil_{motivo}", f"UserDebil_{motivo}", pwd_debil)

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
            
    # --- Nuevos Tests de Seguridad Adicionales ---

    def test_seguridad_confidencialidad_clave_maestra_no_en_claro(self):
        """Verifica que la clave maestra no se almacena en claro."""
        # La clave maestra original no debe ser igual al atributo _clave_maestra_hashed (incluso si este fuera str)
        # y _clave_maestra_hashed debe ser bytes (de bcrypt)
        self.assertIsInstance(self.gestor._clave_maestra_hashed, bytes)
        self.assertNotEqual(self.gestor._clave_maestra_hashed.decode('latin-1', errors='ignore'), self.clave_maestra_valida) # Latin-1 para evitar UnicodeError si no es texto
        
        # Verificar que no podemos "autenticar" el hash contra sí mismo como si fuera la clave en claro
        self.assertFalse(self.gestor._verificar_clave(self.gestor._clave_maestra_hashed, self.gestor._clave_maestra_hashed))


    def test_seguridad_inyeccion_nombre_usuario(self):
        """Verifica la protección contra inyección en nombres de usuario."""
        casos_inyeccion_usuario = ["user;", "user|mal", "user&", "user'--"]
        for usuario_inyectado in casos_inyeccion_usuario:
            with self.subTest(usuario=usuario_inyectado):
                with self.assertRaises(ViolationError): # icontract para usuario añadido
                    self.gestor.añadir_credencial(
                        self.clave_maestra_valida,
                        "ServicioParaUserIny",
                        usuario_inyectado,
                        self.password_robusta
                    )

    def test_seguridad_verificar_credencial_inexistente_usuario_diferente(self):
        """Error al verificar contraseña de un usuario que no existe en un servicio que sí existe."""
        servicio = "ServicioExistente"
        usuario_existente = "UsuarioExistente"
        self.gestor.añadir_credencial(self.clave_maestra_valida, servicio, usuario_existente, self.password_robusta)
        
        with self.assertRaises(ErrorServicioNoEncontrado):
            self.gestor.verificar_password(self.clave_maestra_valida, servicio, "UsuarioInexistente", self.password_robusta)

    def test_seguridad_eliminar_credencial_inexistente_servicio_diferente(self):
        """Error al eliminar credencial de un servicio que no existe."""
        with self.assertRaises(ErrorServicioNoEncontrado):
            self.gestor.eliminar_credencial(self.clave_maestra_valida, "ServicioInexistenteParaElim", "UsuarioCualquiera")

    def test_seguridad_listar_servicios_con_gestor_vacio_tras_eliminacion(self):
        """Verifica que listar servicios devuelve lista vacía si se eliminan todas las credenciales."""
        s1 = "ServUnico1"
        u1 = "UserUnico1"
        self.gestor.añadir_credencial(self.clave_maestra_valida, s1, u1, self.password_robusta)
        self.assertCountEqual(self.gestor.listar_servicios(self.clave_maestra_valida), [s1])
        
        self.gestor.eliminar_credencial(self.clave_maestra_valida, s1, u1)
        self.assertEqual(self.gestor.listar_servicios(self.clave_maestra_valida), [])
        
    def test_seguridad_añadir_credencial_con_password_vacia_falla_politica(self):
        """Verifica que una contraseña vacía es rechazada por la política."""
        with self.assertRaises(ErrorPoliticaPassword):
            self.gestor.añadir_credencial(self.clave_maestra_valida, "ServicioPwdVacia", "UserPwdVacia", "")
            
    def test_seguridad_añadir_credencial_con_nombre_servicio_vacio_falla_icontract(self):
        """Verifica que un nombre de servicio vacío es rechazado por icontract."""
        with self.assertRaises(ViolationError): # icontract @require(lambda servicio, usuario: bool(servicio and usuario))
            self.gestor.añadir_credencial(self.clave_maestra_valida, "", "UserValido", self.password_robusta)

    def test_seguridad_añadir_credencial_con_nombre_usuario_vacio_falla_icontract(self):
        """Verifica que un nombre de usuario vacío es rechazado por icontract."""
        with self.assertRaises(ViolationError): # icontract @require(lambda servicio, usuario: bool(servicio and usuario))
            self.gestor.añadir_credencial(self.clave_maestra_valida, "ServicioValido", "", self.password_robusta)


if __name__ == "__main__":
    unittest.main()