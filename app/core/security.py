# Importa las librerías necesarias.
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from fastapi import HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from typing import List
import secrets

# Carga las variables de entorno
load_dotenv()

# Obtiene las variables de entorno
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))


# Crea un esquema de OAuth2 con una URL de token. 
# OAuth2PasswordBearer es un esquema de autenticación que usa un esquema de bearer con OAuth 2.
# Esto significa que el cliente (el código de usuario en el navegador, móvil, etc.) enviará el token en el encabezado de Autorización con el valor de Bearer y el token.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# Configura un contexto para Passlib. 
# Passlib es una biblioteca de Python para manejar contraseñas. 
# Aquí, se configura para usar el esquema bcrypt para hashear contraseñas, que es una opción segura y recomendada.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Genera una clave segura utilizando la función token_hex de la librería secrets, que se utiliza para generar tokens seguros.
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Función para obtener el hash de una contraseña.
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# Función para verificar si una contraseña coincide con un hash.
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# Función para crear un token de acceso JWT. Este token puede tener un tiempo de expiración y una lista de roles de usuario.
def create_access_token(data: dict, expires_delta: timedelta = None, user_roles: List[str] = None) -> str:
    to_encode = data.copy()
    if user_roles:
        to_encode.update({"roles": user_roles})
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Función para crear un token de actualización. Este token se utiliza para obtener un nuevo token de acceso cuando el token de acceso expira.
def create_refresh_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=7)  # El tiempo de expiración por defecto es de 7 días
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Función para verificar un token de actualización. 
# Esta función decodifica el token, verifica que contenga un user_id y si no lo tiene, lanza una excepción HTTP.
def verify_refresh_token(refresh_token: str, db: Session):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user_id
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Función para crear un token para la recuperación de contraseña. 
# Este token se utiliza para verificar la identidad del usuario cuando intenta restablecer su contraseña. 
def create_password_recovery_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=1)  # 1 día para expirar
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
