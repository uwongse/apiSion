# Importamos las bibliotecas necesarias
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from typing import List
from datetime import timedelta
from ..schemas.schemas import Password
from ..crud.crud import get_users, create_user, authenticate_user, get_user_by_refresh_token, verify_password, change_password  
from ..schemas.schemas import User, UserCreate, Token, RefreshToken  
from ..core.dependencies import get_current_user, get_current_role, admin_role_required, user_role_required, admin_or_user_role_required
from ..core.security import ALGORITHM, SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token
from ..core.database import get_db
from datetime import datetime

# Inicializamos APIRouter
router = APIRouter()

# Este endpoint se utiliza para obtener todos los usuarios de la base de datos.
# Dependencia admin_or_user_role_required verifica que el usuario actual tenga un rol de administrador o de usuario.
@router.get("/test_db", response_model=List[User])
def test_db(role: List[str] = Depends(admin_or_user_role_required), db: Session = Depends(get_db)):
    try:
        users = get_users(db)
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Este endpoint se utiliza para obtener todos los usuarios de la base de datos.
# La dependencia get_current_user verifica que el usuario actual esté autenticado.
@router.get("/allusers", response_model=List[User])
def test_db(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        users = get_users(db)
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Este endpoint se utiliza para crear un nuevo usuario.
@router.post("/users", response_model=User)
def create_new_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = create_user(db=db, user=user)
    user_roles = [role.to_dict()["NombreRol"] for role in db_user.user_roles]

    # Creamos tokens de acceso y actualización
    data = {"sub": db_user.NombreUsuario, "user_id": db_user.UsuarioID}
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data=data, expires_delta=access_token_expires, user_roles=user_roles
    )

    refresh_token_expires = timedelta(days=7)  # Puedes ajustar este valor según tus necesidades
    refresh_token = create_access_token(
        data=data, expires_delta=refresh_token_expires, user_roles=user_roles
    )

    # Guardamos el token de actualización en el modelo de usuario
    db_user.RefreshToken = refresh_token
    db_user.RefreshTokenExpiry = datetime.utcnow() + refresh_token_expires
    db.commit()

    db_user = db_user.to_dict()
    db_user["user_roles_names"] = user_roles
    db_user["access_token"] = access_token
    db_user["refresh_token"] = refresh_token
    return db_user

# Este endpoint se utiliza para iniciar sesión y obtener un token de acceso y actualización.
@router.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Autenticamos al usuario
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Creamos tokens de acceso y actualización
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    user_roles = [role.to_dict()["NombreRol"] for role in user.user_roles]
    data = {"sub": user.NombreUsuario, "user_id": user.UsuarioID}
    access_token = create_access_token(
        data=data, expires_delta=access_token_expires, user_roles=user_roles
    )

    refresh_token_expires = timedelta(days=7)  # Puedes ajustar este valor según tus necesidades
    refresh_token = create_access_token(
        data=data, expires_delta=refresh_token_expires, user_roles=user_roles
    )

    # Guardamos el token de actualización en el modelo de usuario
    user.RefreshToken = refresh_token
    user.RefreshTokenExpiry = datetime.utcnow() + refresh_token_expires
    db.commit()

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

# Este endpoint se utiliza para actualizar el token de acceso usando el token de actualización.
@router.post("/refresh_token", response_model=Token)
def refresh_token(token: RefreshToken, db: Session = Depends(get_db)):
    refresh_token = token.refresh_token
    user = get_user_by_refresh_token(db, refresh_token)
    if user is None or user.RefreshTokenExpiry < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Creamos un nuevo token de acceso y actualización
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    user_roles = [role.to_dict()["NombreRol"] for role in user.user_roles]
    data = {"sub": user.NombreUsuario, "user_id": user.UsuarioID}
    access_token = create_access_token(
        data=data, expires_delta=access_token_expires, user_roles=user_roles
    )

    refresh_token_expires = timedelta(days=7)  # Puedes ajustar este valor según tus necesidades
    new_refresh_token = create_access_token(
        data=data, expires_delta=refresh_token_expires, user_roles=user_roles
    )

    # Guardamos el nuevo token de actualización en el modelo de usuario
    user.RefreshToken = new_refresh_token
    user.RefreshTokenExpiry = datetime.utcnow() + refresh_token_expires
    db.commit()

    return {"access_token": access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}

# Este endpoint se utiliza para obtener los datos del usuario actual.
@router.get("/user/me", response_model=User)
def read_users_me(current_user: User = Depends(get_current_user)):
    """
    Get current user.
    """
    return current_user

# Este endpoint se utiliza para cambiar la contraseña del usuario actual.

@router.post("/change_password")
# Función para cambiar la contraseña del usuario actual
def change_password_endpoint(
    password: Password, 
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not verify_password(password.old_password, current_user.Contrasena):
        raise HTTPException(status_code=400, detail="Incorrect old password")

    try:
        change_password(db=db, user=current_user, new_password=password.new_password)
        return {"message": "Password changed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/logout")
# Función para cerrar la sesión del usuario actual
def logout(current_user: User = Depends(get_current_user)):
    """
    This endpoint is used to logout user, even though it doesn't invalidate the token,
    it gives a chance to user interfaces to trigger this endpoint when user wants to logout,
    then UI can delete the token from the local storage.
    """
    return {"detail": "Successfully logged out"}

