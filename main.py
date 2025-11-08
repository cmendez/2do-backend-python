import os
from fastapi import FastAPI, Depends, HTTPException, status
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
        orm_mode = True


# --- 3. INICIALIZACIÓN DE FASTAPI (Sin cambios) ---
app = FastAPI(title="API de Artículos (Python)")


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

def get_user_by_username(db: Session, username: str):
    """Busca un usuario en la BD por su username"""
    # Asumimos que tu app RealWorld usa email para login
    # ¡Ajusta esto si usa 'username'!
    return db.query(UserTable).filter(UserTable.email == username).first()

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
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decodifica el token
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub") # Asumimos que guardamos el user en "sub"
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    # Busca al usuario en la BD
    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    
    # Devuelve el objeto User de la BD
    return user


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
    # 1. Busca al usuario
    # (El spec de RealWorld usa email como username en el login)
    user = get_user_by_username(db, username=form_data.username)
    
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
        data={"sub": user.email}, # Guardamos el email en el payload
        expires_delta=access_token_expires
    )
    
    # 4. Devuelve el token
    return {"access_token": access_token, "token_type": "bearer"}


# --- ENDPOINT DE ARTÍCULOS (AHORA PROTEGIDO) ---
@app.get("/api/articles", response_model=List[ArticleResponse])
def get_all_articles(
    db: Session = Depends(get_db),
    # NUEVO: Esta dependencia protege el endpoint
    current_user: UserTable = Depends(get_current_user) 
):
    """
    Endpoint para LEER todos los artículos.
    Ahora solo funciona si se provee un Token Bearer válido.
    """
    print(f"¡Petición recibida de un usuario autenticado: {current_user.email}!")
    
    articles = db.query(ArticleTable).all()
    return articles