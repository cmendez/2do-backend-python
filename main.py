import os
from fastapi import FastAPI, Depends, HTTPException, status, Header
from pydantic import BaseModel
from typing import List, Optional

# --- SQLAlchemy (Manejo de Base de Datos) ---
from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# --- JWT y Seguridad ---
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# Middleware de CORS
from fastapi.middleware.cors import CORSMiddleware

# ==============================================================================
# --- 1. CONFIGURACIÓN DE BASE DE DATOS (CORREGIDA PARA RENDER/TiDB) ---
# ==============================================================================

# Leemos las variables de entorno. 
# Usamos 'get' sin valor por defecto para obligar a usar las de Render.
DB_USER = os.getenv("DB_USERNAME") or os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_DATABASE") or os.getenv("DB_NAME")
DB_HOST = os.getenv("DB_HOST") # Antes tenías "host.docker.internal"
DB_PORT = os.getenv("DB_PORT") # Antes tenías 33066

# --- DEBUGGING: Verificamos en logs qué está leyendo Python ---
print(f"\n--- INICIANDO CONEXIÓN A BASE DE DATOS ---")
print(f"DB_HOST: {DB_HOST}")
print(f"DB_PORT: {DB_PORT}")
print(f"DB_USER: {DB_USER}")
# -------------------------------------------------------------

# Construcción de la URL de conexión
DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# --- CONFIGURACIÓN SSL (VITAL PARA TIDB) ---
connect_args = {}

# Detectamos si estamos usando TiDB (o si estamos en Producción) para inyectar el certificado
if DB_HOST and ("tidb" in DB_HOST or "aws" in DB_HOST):
    print("🔒 Detectado TiDB/Cloud: Activando modo SSL seguro...")
    connect_args = {
        "ssl": {
            "ca": "/etc/ssl/certs/ca-certificates.crt"
        }
    }

# Creación del motor con opciones de reconexión (pool_pre_ping)
engine = create_engine(
    DATABASE_URL, 
    connect_args=connect_args,
    pool_pre_ping=True 
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- Configuración de Seguridad JWT ---

# Intentamos leer con varios nombres comunes
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY") or os.getenv("SECRET_KEY")

# VALIDACIÓN CRÍTICA: Si después de intentar leerla sigue siendo None, detenemos todo.
# Esto te ayudará a ver el error en los logs inmediatamente al arrancar.
if not JWT_SECRET_KEY:
    print("❌ ERROR FATAL: No se encontró la variable de entorno JWT_SECRET_KEY o SECRET_KEY.")
    # Usamos una clave dummy SOLO para que no explote el arranque, pero avisamos del error
    # OJO: En producción esto debería detener la app, pero para debug lo dejamos así.
    JWT_SECRET_KEY = "clave_temporal_insegura_para_debug" 

ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

print(f"🔒 Configuración JWT cargada. Algoritmo: {ALGORITHM}")
# Nunca imprimas la clave secreta completa en logs, pero sí podemos ver si tiene longitud
print(f"🔑 Longitud de clave secreta: {len(JWT_SECRET_KEY) if JWT_SECRET_KEY else 0}")

# Contexto de Passlib: le decimos que use 'bcrypt'
# Esto verificará automáticamente los hashes de bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Esquema de seguridad: le dice a FastAPI que busque un "Bearer Token"
# en la URL /api/users/login (la crearemos más abajo)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/users/login")


# ==============================================================================
# --- 2. MODELOS (Definición de Datos) ---
# ==============================================================================

# Modelo ORM para 'articles' (Sin cambios)
class ArticleTable(Base):
    __tablename__ = "articles"
    id = Column(Integer, primary_key=True, index=True)
    slug = Column(String(255), unique=True, index=True)
    title = Column(String(255))
    description = Column(Text)
    body = Column(Text)

# --- NUEVO: Modelo ORM para 'users' ---
# DEBES AJUSTAR ESTO para que coincida con tu tabla 'users' de RealWorld
class UserTable(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    email = Column(String(255), unique=True, index=True)
    password = Column(String(255)) 


# --- Schemas Pydantic ---

# El JSON que devolveremos en el login
class Token(BaseModel):
    access_token: str
    token_type: str

# El contenido (payload) que guardaremos DENTRO del JWT
class TokenData(BaseModel):
    username: str | None = None


# Modelo de Respuesta (Pydantic) para 'Article' (Sin cambios)
class ArticleResponse(BaseModel):
    slug: str
    title: str
    description: Optional[str] = None
    body: Optional[str] = None
    
    class Config:
        from_attributes = True


# ==============================================================================
# --- 3. INICIALIZACIÓN DE FASTAPI Y CORS ---
# ==============================================================================
app = FastAPI(title="API de Artículos (Python)")

# Configuración CORS Flexible para la Demo
origins = [
    "http://localhost:4200",
    "https://upch-slim-php-realworld.onrender.com", # Tu backend PHP (opcional)
    "*" # PERMITIR TODO (Para evitar bloqueos en la demo con Vercel)
]

# Si configuraste la variable en Render, úsala, si no, usa la lista de arriba
cors_env = os.getenv("CORS_ALLOWED_ORIGINS")
if cors_env:
    if cors_env == "*":
        origins = ["*"]
    else:
        origins = cors_env.split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # Permite todos los métodos (GET, POST, etc.)
    allow_headers=["*"], # Permite todas las cabeceras (incluyendo Authorization)
)


# ==============================================================================
# --- 4. DEPENDENCIAS Y UTILIDADES ---
# ==============================================================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- NUEVO: Funciones de Utilidad de Autenticación ---

def verify_password(plain_password, hashed_password):
    """Verifica la contraseña contra el hash de la BD"""
    return pwd_context.verify(plain_password, hashed_password)

def get_user_by_sub(db: Session, sub_value: str):
    """Busca un usuario en la BD por el valor del 'sub' (que es el username)"""
    return db.query(UserTable).filter(UserTable.username == sub_value).first()

def get_user_by_email(db: Session, email: str):
    """Busca un usuario en la BD por su email"""
    return db.query(UserTable).filter(UserTable.email == email).first()

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Crea un nuevo token JWT"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Dependencia para OBTENER el usuario actual ---
# Esta es la función que "protege" los endpoints
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Simplificado para producción (menos logs, más velocidad)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = get_user_by_sub(db, sub_value=username)
    if user is None:
        raise credentials_exception
    
    return user

async def get_current_user_optional(
    authorization: Optional[str] = Header(None), 
    db: Session = Depends(get_db)
) -> Optional[UserTable]:
    
    if authorization is None:
        return None
    
    token_parts = authorization.split(" ")
    if len(token_parts) != 2 or token_parts[0] != "Bearer":
        return None
    
    # ¡¡ESTA ES LA LÍNEA QUE FALTABA!!
    token = token_parts[1]
    
    try:
        # Ahora 'token' sí existe
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        
        user = get_user_by_sub(db, sub_value=username)
        return user 
    
    except JWTError:
        return None

# --- 5. ENDPOINTS ---
# ==============================================================================

# --- Endpoint de Login ---
@app.post("/api/users/login", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: Session = Depends(get_db)
):
    """
    Recibe un email (en campo 'username') y 'password'
    Valida al usuario y devuelve un token JWT.
    """
    # 1. Busca al usuario POR EMAIL (usando la nueva función)
    user = get_user_by_email(db, email=form_data.username) # form_data.username ES el email
    
    # 2. Valida la contraseña
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 3. Crea el token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        # ¡IMPORTANTE! Pone el USERNAME en el sub (para coincidir con PHP)
        data={"sub": user.username}, 
        expires_delta=access_token_expires
    )
    
    # 4. Devuelve el token
    return {"access_token": access_token, "token_type": "bearer"}

# --- RUTA DE PRUEBA DE SANIDAD ---
@app.get("/api/hello")
def get_hello():
    return {"message": "¡Conexión exitosa a TiDB desde Render!"}

# --- ENDPOINT DE ARTÍCULOS (AHORA PROTEGIDO) ---
@app.get("/api/articles", response_model=List[ArticleResponse])
def get_all_articles(
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_user) 
):
    """
    Endpoint PROTEGIDO para LEER todos los artículos.
    """
    # Ya sabemos que el usuario existe, si no, habría fallado con 401.
    print(f"¡Petición recibida de un usuario autenticado: {current_user.email}!", flush=True)
    
    articles = db.query(ArticleTable).all()
    return articles