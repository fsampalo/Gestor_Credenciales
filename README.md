# Gestor de Credenciales

Un **Gestor de Credenciales** simple y seguro diseñado bajo la filosofía **STDD (Simple Things Done Differently)**. Este proyecto ofrece una solución innovadora para almacenar, gestionar y proteger credenciales de forma eficiente, priorizando la simplicidad y una experiencia de usuario única.

## Filosofía STDD
En este proyecto, aplicamos **STDD**:
- **Simplicidad**: Interfaz y lógica minimalistas para un uso intuitivo.
- **Diferencia**: Enfoques no convencionales para la gestión de credenciales, como [menciona alguna característica única, ej. encriptación local o categorización dinámica].
- **Funcionalidad**: Solo las características esenciales, bien ejecutadas, para evitar complejidad innecesaria.

## Características
- Almacenamiento seguro de credenciales con encriptación.
- Interfaz de consola ligera y fácil de usar.
- Organización intuitiva de credenciales por categorías o servicios.
- Generación automática de contraseñas seguras (opcional).
- Compatible con múltiples plataformas.

## Instalación
1. Clona el repositorio:
   ```bash
   git clone https://github.com/tu-usuario/gestor-credenciales.git
   ```
2. Navega al directorio del proyecto:
   ```bash
   cd gestor-credenciales
   cd GestorCredenciales
   ```

## Uso
1. Arrancamos las pruebas unitarias:
   ```bash
   python -m pytest tests/gestor_credenciales/test_seguridad_gestor_credenciales.py -v
   ```

## Estructura del Proyecto
```
gestor-credenciales/
├── src/
│   └── gestor_credenciales/
│       ├── gestor_credenciales.py  # Lógica principal
│       └── utils.py               # Funciones auxiliares
├── tests/
│   └── gestor_credenciales/       # Pruebas unitarias y funcionales
├── requirements.txt               # Dependencias del proyecto
└── README.md                     # Este archivo
```
