from sqlalchemy import Column, Integer, String, Enum, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base

# Creación de la base declarativa para modelos SQLAlchemy
Base = declarative_base()

# Definición de la clase Usuario para representar la tabla 'usuarios' en la base de datos
class User(Base):
    __tablename__ = 'usuarios'
     # Definición de las columnas para la tabla 'usuarios'
    UsuarioID = Column(Integer, primary_key=True)
    NombreUsuario = Column(String(50), nullable=False)
    CorreoElectronico = Column(String(100), nullable=False)
    Contrasena = Column(String(60), nullable=False)
    FechaCreacion = Column(DateTime, default=func.now())
    FechaActualizacion = Column(DateTime)
    Idioma = Column(Enum('Español', 'English'), default='Español')
    ZonaHoraria = Column(String(8), default='GMT+1')
    Token = Column(String(50))
    PuntosLealtad = Column(Integer, default=0)
    RefreshToken = Column(String(255))
    RefreshTokenExpiry = Column(DateTime)
    # Aquí definimos las columnas de la tabla y las relaciones con otras tablas
    # Definición de la relación con la tabla 'usuariosroles'
    user_roles = relationship("UserRoles", back_populates="user")
    user_roles_names = []  # Nuevo campo
    # Esta función convierte una instancia de la clase Usuario en un diccionario
    # para que pueda ser devuelta por la API como un objeto JSON
    def to_dict(self):
        return {
            "UsuarioID": self.UsuarioID,
            "NombreUsuario": self.NombreUsuario,
            "CorreoElectronico": self.CorreoElectronico,
            "Contrasena": self.Contrasena,
            "FechaCreacion": self.FechaCreacion,
            "FechaActualizacion": self.FechaActualizacion,
            "Idioma": self.Idioma,
            "ZonaHoraria": self.ZonaHoraria,
            "Token": self.Token,
            "RefreshToken":self.RefreshToken,
            "RefreshTokenExpiry":self.RefreshTokenExpiry,
            "PuntosLealtad": self.PuntosLealtad,
            "user_roles": [role.to_dict() for role in self.user_roles],
            "user_roles_names": self.user_roles_names  # Incluimos el nuevo campo aquí
        }
# Definición de la clase Role para representar la tabla 'rolesusuarios' en la base de datos
class Role(Base):
    __tablename__ = 'rolesusuarios'
    
    RolID = Column(Integer, primary_key=True)
    NombreRol = Column(String(50), nullable=False)
    DescripcionRol = Column(String(200), nullable=False)

    role_users = relationship("UserRoles", back_populates="role")
    
# Definimos la clase UserRoles que representa la asociación entre usuarios y roles
# Definición de la clase UserRoles para representar la tabla 'usuariosroles' en la base de datos
class UserRoles(Base):
    __tablename__ = 'usuariosroles'
    
    UsuariosRolesID = Column(Integer, primary_key=True)
    UsuarioID = Column(Integer, ForeignKey('usuarios.UsuarioID'), nullable=False)
    RolID = Column(Integer, ForeignKey('rolesusuarios.RolID'), nullable=False)

    user = relationship("User", back_populates="user_roles")
    role = relationship("Role", back_populates="role_users")
    # Función para convertir una instancia de UserRoles a un diccionario
    # Esta función convierte una instancia de la clase UserRoles en un diccionario
    # para que pueda ser devuelta por la API como un objeto JSON
    def to_dict(self):
        return {
            "UsuariosRolesID": self.UsuariosRolesID,
            "UsuarioID": self.UsuarioID,
            "RolID": self.RolID,
            "NombreRol": self.role.NombreRol  # Agrega el nombre del rol aquí
        }