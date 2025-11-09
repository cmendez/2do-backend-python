import os
from fastapi import FastAPI, Depends, HTTPException, status, Header
from pydantic import BaseModel
from typing import List, Optional

# --- SQLAlchemy (Manejo de Base de Datos) ---
from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# --- NUEVO: Importaciones para JWT y Seguridad ---
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# NUEVO: Importa el Middleware de CORS
from fastapi.middleware.cors import CORSMiddleware

# --- 1. CONFIGURACIÓN DE BASE DE DATOS (Sin cambios) ---

DB_USER = os.getenv("DB_USERNAME")
DB_PASS = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_DATABASE")
DB_HOST = "host.docker.internal"
DB_PORT = 33066
DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- NUEVO: Configuración de Seguridad JWT ---

# Leemos las variables del .env
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# Contexto de Passlib: le decimos que use 'bcrypt'
# Esto verificará automáticamente los hashes de bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Esquema de seguridad: le dice a FastAPI que busque un "Bearer Token"
# en la URL /api/users/login (la crearemos más abajo)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/users/login")


# --- 2. MODELOS (Definición de Datos) ---

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
    password = Column(String(255)) # Asumimos que esta columna guarda el hash


# --- NUEVO: Schemas Pydantic para Autenticación ---

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


# --- 3. INICIALIZACIÓN DE FASTAPI (Sin cambios) ---
app = FastAPI(title="API de Artículos (Python)")

# --- NUEVO: AÑADIR MIDDLEWARE DE CORS ---
# Define de dónde permitimos peticiones (tu app de Angular)
origins = [
    "http://localhost:4200",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # Permite todos los métodos (GET, POST, etc.)
    allow_headers=["*"], # Permite todas las cabeceras (incluyendo Authorization)
)

# --- 4. DEPENDENCIA DE SESIÓN (Sin cambios) ---
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

# --- NUEVO: Dependencia para OBTENER el usuario actual ---
# Esta es la función que "protege" los endpoints
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Decodifica el token, valida al usuario y lo devuelve.
    Si algo falla, lanza una excepción HTTP 401.
    """
    
    print("\n--- DEBUG: INICIO DE get_current_user ---", flush=True)
    print(f"DEBUG: Token recibido: {token[:20]}...", flush=True)
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        print(f"DEBUG: Payload decodificado: {payload}", flush=True)
        
        username: str = payload.get("sub")
        if username is None:
            print("DEBUG: ¡Error! 'sub' no está en el payload.", flush=True)
            raise credentials_exception
        
        print(f"DEBUG: Buscando en BD con sub: {username}", flush=True)
        
    except JWTError as e:
        print(f"DEBUG: ¡Error! JWT.decode falló. ¿Clave secreta incorrecta? {e}", flush=True)
        raise credentials_exception
    
    user = get_user_by_sub(db, sub_value=username)
    print(f"DEBUG: Resultado de la BD: {user}", flush=True)
    
    if user is None:
        print("DEBUG: ¡Error! Usuario no encontrado en la BD.", flush=True)
        raise credentials_exception
    
    print(f"DEBUG: Usuario autenticado: {user.username}", flush=True)
    print("--- DEBUG: FIN DE get_current_user ---\n", flush=True)
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

# --- NUEVO: Endpoint de Login ---
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
    return {"message": "¡El código SÍ se actualizó!"}
# --- FIN DE RUTA DE PRUEBA ---

# --- ENDPOINT DE ARTÍCULOS (AHORA PROTEGIDO) ---
@app.get("/api/articles", response_model=List[ArticleResponse])
def get_all_articles(
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_user) # Correcto
):
    """
    Endpoint PROTEGIDO para LEER todos los artículos.
    """
    # Ya sabemos que el usuario existe, si no, habría fallado con 401.
    print(f"¡Petición recibida de un usuario autenticado: {current_user.email}!", flush=True)
    
    articles = db.query(ArticleTable).all()
    return articles