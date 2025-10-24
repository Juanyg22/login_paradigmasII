from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import os

from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from dotenv import load_dotenv

# =========================
# Config
# =========================
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "cambia_esto_por_un_valor_secreto_muy_largo")
JWT_ALG = "HS256"
JWT_EXP_MIN = 120  # minutos

app = Flask(__name__)
CORS(app, supports_credentials=True)

# =========================
# Dominio (POO)
# =========================
@dataclass
class Rol:
    nombre: str
    permisos: List[str] = field(default_factory=list)

    def tiene_permiso(self, accion: str) -> bool:
        return accion.upper() in (p.upper() for p in self.permisos)

@dataclass
class Usuario:
    username: str
    _password_hash: str
    rol: Rol

    @classmethod
    def crear_contrasenia_hash(cls, password_plano: str) -> str:
        return generate_password_hash(password_plano, method="pbkdf2:sha256", salt_length=16)

    def validar_clave(self, password_plano: str) -> bool:
        return check_password_hash(self._password_hash, password_plano)

    def to_public_dict(self) -> Dict:
        return {
            "username": self.username,
            "role": self.rol.nombre,
            "permissions": self.rol.permisos
        }

# =========================
# Roles -> Permisos
# =========================
ROLES: Dict[str, Rol] = {
    "Personal": Rol("Personal", ["LECTURA"]),
    "Jefe de Área": Rol("Jefe de Área", ["LECTURA", "EDICIÓN"]),
    "Gerente": Rol("Gerente", ["LECTURA", "EDICIÓN", "APROBACIÓN"]),
    "Director": Rol("Director", ["LECTURA", "EDICIÓN", "APROBACIÓN", "DECISIÓN"]),
    "Supervisor": Rol("Supervisor", ["LECTURA", "CONTROL"]),
    "Administrador del Sistema": Rol("Administrador del Sistema", ["GESTIÓN_TOTAL"]),
}

# =========================
# "Repositorio" en memoria
# =========================
USUARIOS: Dict[str, Usuario] = {}

def registrar_usuario(username: str, password_plano: str, rol_nombre: str):
    rol = ROLES[rol_nombre]
    user = Usuario(
        username=username,
        _password_hash=Usuario.crear_contrasenia_hash(password_plano),
        rol=rol
    )
    USUARIOS[username] = user

# Usuarios demo
registrar_usuario("juan", "1234", "Personal")
registrar_usuario("ana", "claveSegura", "Administrador del Sistema")

# =========================
# JWT utils
# =========================
def emitir_jwt(usuario: Usuario) -> str:
    payload = {
        "sub": usuario.username,
        "role": usuario.rol.nombre,
        "permissions": usuario.rol.permisos,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXP_MIN),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALG)

def verificar_jwt(token: str) -> Optional[Dict]:
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
        return data
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def obtener_usuario(username: str) -> Optional[Usuario]:
    return USUARIOS.get(username)

from functools import wraps

def requiere_permiso(permisos_requeridos):
    """Decorador que valida el JWT y comprueba si el usuario tiene los permisos dados"""
    def decorador(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "Token faltante"}), 401

            token = auth.split(" ", 1)[1]
            data = verificar_jwt(token)
            if not data:
                return jsonify({"error": "Token inválido o expirado"}), 401

            usuario = obtener_usuario(data["sub"])
            if not usuario:
                return jsonify({"error": "Usuario no encontrado"}), 404

            # Verificar permisos
            if not any(p in usuario.rol.permisos for p in permisos_requeridos):
                return jsonify({"error": "Acceso denegado. Permiso insuficiente."}), 403

            # Pasar el usuario al endpoint si todo bien
            return func(usuario, *args, **kwargs)
        return wrapper
    return decorador

# =========================
# Endpoints
# =========================
@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    user = obtener_usuario(username)
    if not user or not user.validar_clave(password):
        return jsonify({"error": "Credenciales inválidas"}), 401

    token = emitir_jwt(user)
    return jsonify({"token": token, "user": user.to_public_dict()}), 200

@app.get("/auth/me")
def me():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Falta token"}), 401

    token = auth.split(" ", 1)[1]
    data = verificar_jwt(token)
    if not data:
        return jsonify({"error": "Token inválido o expirado"}), 401

    user = obtener_usuario(data["sub"])
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    return jsonify({"user": user.to_public_dict()}), 200

# =========================
# Endpoints protegidos
# =========================

@app.get("/ver")
@requiere_permiso(["LECTURA"])
def ver(usuario):
    return jsonify({
        "mensaje": f"Hola {usuario.username}, tenés permiso de LECTURA.",
        "rol": usuario.rol.nombre
    })

@app.get("/editar")
@requiere_permiso(["EDICIÓN"])
def editar(usuario):
    return jsonify({
        "mensaje": f"{usuario.username} puede editar.",
        "rol": usuario.rol.nombre
    })

@app.get("/aprobar")
@requiere_permiso(["APROBACIÓN"])
def aprobar(usuario):
    return jsonify({
        "mensaje": f"{usuario.username} puede aprobar documentos.",
        "rol": usuario.rol.nombre
    })

@app.get("/admin")
@requiere_permiso(["GESTIÓN_TOTAL"])
def admin(usuario):
    return jsonify({
        "mensaje": f"Acceso completo, {usuario.username}.",
        "rol": usuario.rol.nombre
    })

# =========================
# Arranque
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
