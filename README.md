* Proyecto desarrollado para la materia Paradigmas y Lenguajes de Programación II.
Implementa un sistema de autenticación y autorización basado en roles (RBAC) utilizando Flask (Python) como backend y Framer como interfaz web.
Incluye despliegue completo en Render y separación de responsabilidades mediante POO y principios SOLID.

Tecnologías utilizadas:
* Backend: Flask (Python 3.10)
* Frontend: Framer (React + TypeScript)
* Autenticación: JWT (JSON Web Token)
* Base de datos simulada: Diccionario en memoria (usuarios y roles)
* Despliegue: Render
* Diseño: Framer (UI con navegación /login, /dashboard, /admin)

Funcionalidades principales:
* Inicio de sesión con validación de credenciales.
* Generación de token JWT seguro con SECRET_KEY.
* Autorización por rol y permiso: acceso restringido a endpoints según permisos asociados.
* Rutas protegidas: /ver, /editar, /aprobar, /admin.
* Frontend conectado al backend en Render (fetch API).
* Interfaz moderna: formulario de login, dashboard dinámico y panel de administración

Usuarios de Prueba:
Usuario: juan
Contraseña: 1234
Rol: Personal (solo lectura)

Usuario: ana
Contraseña: claveSegura
Rol: Administrador del sistema (gestion total)

Principios SOLID aplicados:
* S (Responsabilidad única): cada clase tiene un único propósito.

* O (Abierto/Cerrado): se pueden agregar roles sin modificar lógica existente.

* L (Sustitución de Liskov): cualquier subclase de Usuario puede usarse sin romper el código.

* I (Segregación de Interfaces): no se fuerzan métodos innecesarios.

* D (Inversión de Dependencias): la autorización depende de la abstracción Rol, no de implementaciones fijas.


Proyecto realizado por:

Alfaro, Carlos T. - Figueroa, Amorina. - Gonzalez, Juan I. - Viarengo, Gonzalo A.

Universidad de la Cuenca del Plata – 2025

Materia: Paradigmas y Lenguajes de Programación II

Profesores: Mgtr. Arzamendia, Carlos Marcelo y Lic. Del Rosario, Gabriel Dario
