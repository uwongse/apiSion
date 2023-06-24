from typing import List
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from ..core.security import ALGORITHM, SECRET_KEY, oauth2_scheme
from ..core.database import get_db
from ..crud.crud import get_user_by_id
from fastapi.security import OAuth2PasswordBearer  
from ..schemas.schemas import TokenData 


# Esta función se utiliza para obtener el usuario actual a partir del token proporcionado en la solicitud
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id)
    except JWTError:
        raise credentials_exception
    user = get_user_by_id(db, user_id)  # Se ha cambiado get_user_by_token por get_user_by_id
    if user is None:
        raise credentials_exception
    return user

# Esta función se utiliza para obtener el rol del usuario a partir del token proporcionado en la solicitud
def get_current_role(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        roles: List[str] = payload.get("roles")
        if roles is None:
            raise HTTPException(status_code=400, detail="Invalid token")
        return roles
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
# Esta función se utiliza para comprobar si el usuario tiene el rol de administrador
# Se lanza una excepción si el usuario no es un administrador
def admin_role_required(role: List[str] = Depends(get_current_role)):
    if 'Admin' not in role:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return role
# Esta función se utiliza para comprobar si el usuario tiene el rol de usuario
# Se lanza una excepción si el usuario no es un usuario
def user_role_required(role: List[str] = Depends(get_current_role)):
    if 'User' not in role:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return role
# Esta función se utiliza para comprobar si el usuario tiene el rol de administrador o usuario
# Se lanza una excepción si el usuario no es ni un administrador ni un usuario
def admin_or_user_role_required(role: List[str] = Depends(get_current_role)):
    if 'Admin' not in role and 'User' not in role:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return role