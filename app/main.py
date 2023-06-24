# Importa FastAPI, una moderna y rápida (alta performance) framework web para construir APIs con Python 3.6+ basada en las anotaciones de tipo standard de Python.
from fastapi import FastAPI
# Importa CORSMiddleware, un middleware que se encarga de procesar las solicitudes de Control de Acceso de Origen Cruzado (CORS) que son realizadas por los clientes.
from fastapi.middleware.cors import CORSMiddleware
# Importa api_router de las rutas de la API. 
# Este es un enrutador que contiene todas las rutas/endpoints de la API.
from .api.routes import router as api_router

# Crea una nueva aplicación FastAPI.
app = FastAPI()

# Una lista de orígenes que son permitidos para hacer solicitudes CORS.
# Aquí se incluye el localhost y todos los orígenes (*).
origins = [
    'http://localhost:54165',
    '*',
]

# Añade el middleware CORS a la aplicación.
# Este middleware procesará las solicitudes CORS de los clientes.
app.add_middleware(
    CORSMiddleware,
    # Permite solicitudes de los orígenes listados.
    allow_origins=origins,
    # Permite que los orígenes listados hagan solicitudes con credenciales (cookies, headers de autorización).
    allow_credentials=True,
    # Permite todos los métodos de solicitud (GET, POST, PUT, DELETE, etc.) desde los orígenes listados.
    allow_methods=["*"],
)

# Incluye el enrutador de la API en la aplicación.
# Esto añade todas las rutas/endpoints de la API a la aplicación.
app.include_router(api_router) 
