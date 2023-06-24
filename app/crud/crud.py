from sqlalchemy.orm import Session, joinedload
from datetime import datetime
from ..models.models import User, UserRoles
from ..schemas.schemas import UserCreate, UserUpdate
from ..core.security import get_password_hash, verify_password


def get_users(db: Session):
    users = db.query(User).options(joinedload(User.user_roles)).all()
    for user in users:
        user.user_roles_names = [role.to_dict()["NombreRol"] for role in user.user_roles]  
    return [user.to_dict() for user in users]

def create_user(db: Session, user: UserCreate):
    db_user = User(**user.dict())
    db_user.Contrasena = get_password_hash(user.Contrasena)  # Aquí es donde se cambia la contraseña en texto plano por un hash
    db_user.FechaCreacion = datetime.now()

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    user_role = UserRoles(UsuarioID=db_user.UsuarioID, RolID=2)
    db.add(user_role)
    db.commit()

    return db_user

def get_user(db: Session, username: str):
    return db.query(User).filter(User.NombreUsuario == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.Contrasena):
        return False
    return user

def get_user_by_id(db: Session, user_id: int):
    return db.query(User).filter(User.UsuarioID == user_id).first()

def update_user(db: Session, user: UserUpdate):
    db_user = get_user_by_id(db, user.UsuarioID)
    if db_user is None:
        return None
    for var, value in vars(user).items():
        if var == "Contrasena":
            value = get_password_hash(value)
        setattr(db_user, var, value) if value else None
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def delete_user(db: Session, user_id: int):
    user = get_user_by_id(db, user_id)
    db.delete(user)
    db.commit()
    return user

# Nueva función para obtener un usuario por su token
def get_user_by_token(db: Session, token: str):
    return db.query(User).filter(User.Token == token).first()

def get_user_by_refresh_token(db: Session, refresh_token: str):
    return db.query(User).filter(User.RefreshToken == refresh_token).first()

# La función get_user_by_token se ha renombrado a get_user_by_id y su implementación ha sido modificada.
def get_user_by_id(db: Session, user_id: int):
    return db.query(User).filter(User.UsuarioID == user_id).first()

def change_password(db: Session, user: User, new_password: str):
    user.Contrasena = get_password_hash(new_password)
    db.commit()
    return user
