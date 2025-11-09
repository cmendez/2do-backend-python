# Usamos la misma imagen base de la Parte 1
FROM python:3.11-slim

WORKDIR /app

# Copiamos primero el archivo de requisitos
COPY requirements.txt .

# Instalamos las dependencias
RUN pip install -r requirements.txt

# Copiamos el resto del código
COPY . .

# Comando para iniciar el servidor
# Escucha en todas las IPs (0.0.0.0) en el puerto 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]