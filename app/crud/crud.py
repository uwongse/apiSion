# Importamos las bibliotecas necesarias
from sqlalchemy.orm import Session, joinedload
from datetime import datetime
from ..models.models import User, UserRoles
from ..schemas.schemas import UserCreate, UserUpdate
from ..core.security import get_password_hash, verify_password

# Función para obtener todos los usuarios de la base de datos
def get_users(db: Session):
    # Obtiene todos los usuarios de la base de datos con sus roles correspondientes
    users = db.query(User).options(joinedload(User.user_roles)).all()
    # Asigna los nombres de los roles a cada usuario
    for user in users:
        user.user_roles_names = [role.to_dict()["NombreRol"] for role in user.user_roles]  
    # Devuelve una lista de usuarios convertida a diccionarios
    return [user.to_dict() for user in users]

# Función para crear un usuario en la base de datos
def create_user(db: Session, user: UserCreate):
    # Crea un objeto de usuario a partir del esquema proporcionado
    db_user = User(**user.dict())
    # Encripta la contraseña del usuario
    db_user.Contrasena = get_password_hash(user.Contrasena)
    # Asigna la fecha de creación actual al usuario
    db_user.FechaCreacion = datetime.now()

    # Añade el usuario a la base de datos y lo refresca para obtener cualquier cambio realizado durante el commit
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    # Asigna el rol al usuario (en este caso, el RolID se establece en 2 de manera predeterminada)
    user_role = UserRoles(UsuarioID=db_user.UsuarioID, RolID=2)
    db.add(user_role)
    db.commit()

    # Devuelve el objeto de usuario creado
    return db_user

# Función para obtener un usuario de la base de datos por nombre de usuario
def get_user(db: Session, username: str):
    # Devuelve el primer usuario que coincida con el nombre de usuario proporcionado
    return db.query(User).filter(User.NombreUsuario == username).first()

# Función para autenticar un usuario basado en su nombre de usuario y contraseña
def authenticate_user(db: Session, username: str, password: str):
    # Obtiene el usuario por el nombre de usuario
    user = get_user(db, username)
    # Si el usuario no existe, devuelve False
    if not user:
        return False
    # Si la contraseña proporcionada no coincide con la del usuario, devuelve False
    if not verify_password(password, user.Contrasena):
        return False
    # Si el usuario existe y la contraseña coincide, devuelve el objeto de usuario
    return user

# Función para obtener un usuario por su ID de usuario
def get_user_by_id(db: Session, user_id: int):
    # Devuelve el primer usuario que coincida con el ID de usuario proporcionado
    return db.query(User).filter(User.UsuarioID == user_id).first()

# Función para actualizar un usuario en la base de datos
def update_user(db: Session, user: UserUpdate):
    # Obtiene el usuario por el ID de usuario
    db_user = get_user_by_id(db, user.UsuarioID)
    # Si el usuario no existe, devuelve None
    if db_user is None:
        return None
    # Actualiza los campos del usuario con los valores proporcionados, encriptando la contraseña si es necesario
    for var, value in vars(user).items():
        if var == "Contrasena":
            value = get_password_hash(value)
        setattr(db_user, var, value) if value else None
    # Añade el usuario actualizado a la base de datos y lo refresca para obtener cualquier cambio realizado durante el commit
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    # Devuelve el objeto de usuario actualizado
    return db_user

# Función para eliminar un usuario de la base de datos
def delete_user(db: Session, user_id: int):
    # Obtiene el usuario por el ID de usuario
    user = get_user_by_id(db, user_id)
    # Elimina el usuario de la base de datos
    db.delete(user)
    db.commit()
    # Devuelve el objeto de usuario eliminado
    return user

# Función para obtener un usuario por su token de autenticación
def get_user_by_token(db: Session, token: str):
    # Devuelve el primer usuario que coincida con el token proporcionado
    return db.query(User).filter(User.Token == token).first()

# Función para obtener un usuario por su token de actualización
def get_user_by_refresh_token(db: Session, refresh_token: str):
    # Devuelve el primer usuario que coincida con el token de actualización proporcionado
    return db.query(User).filter(User.RefreshToken == refresh_token).first()

# Función para cambiar la contraseña de un usuario
def change_password(db: Session, user: User, new_password: str):
    # Encripta la nueva contraseña y la asigna al usuario
    user.Contrasena = get_password_hash(new_password)
    # Comete el cambio en la base de datos
    db.commit()
    # Devuelve el objeto de usuario con la contraseña actualizada
    return user
