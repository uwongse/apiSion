from typing import Optional, List
from pydantic import BaseModel
from datetime import date

# Definición base del esquema del usuario, contiene campos comunes
class UserBase(BaseModel):
    NombreUsuario: str
    CorreoElectronico: str
    Idioma: Optional[str] = "Español"
    ZonaHoraria: Optional[str] = "GMT+1"

# Modelo para la creación de un usuario. Hereda de UserBase y añade el campo Contrasena
class UserCreate(UserBase):
    Contrasena: str

# Modelo para actualizar un usuario. Similar a UserCreate pero la contraseña es opcional
class UserUpdate(UserBase):
    Contrasena: Optional[str] = None

# Modelo base para la relación entre usuario y rol
class UserRoleBase(BaseModel):
    UsuariosRolesID: int
    UsuarioID: int
    RolID: int
    NombreRol: str  # Agrega el nombre del rol aquí

# Modelo base para el esquema del rol
class RoleBase(BaseModel):
    NombreRol: str
    DescripcionRol: str

# Modelo final para el usuario. Hereda de UserBase y añade campos adicionales.
class User(UserBase):
    UsuarioID: int
    FechaCreacion: Optional[date]
    FechaActualizacion: Optional[date]
    Token: Optional[str] = None
    PuntosLealtad: Optional[int] = 0
    user_roles_names: List[str]  # Nuevo campo
    access_token: Optional[str] = None  # New field
    refresh_token: Optional[str] = None  # New field

    class Config:
        orm_mode = True  # Permite la compatibilidad con los modelos ORM de SQLAlchemy

# Modelo final para el rol. Hereda de RoleBase y añade campos adicionales.
class Role(RoleBase):
    RolID: int
    role_users: List[UserRoleBase]

    class Config:
        orm_mode = True  # Permite la compatibilidad con los modelos ORM de SQLAlchemy

# Modelo para el token JWT
class Token(BaseModel):
    access_token: str
    refresh_token: str  # Nuevo campo
    token_type: str
    roles: List[str] = []  # Nuevo campo

# Modelo para los datos del token JWT
class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None

# Modelo para el token de refresco
class RefreshToken(BaseModel):
    refresh_token: str

# Modelo para cambiar la contraseña
class Password(BaseModel):
    old_password: str
    new_password: str
