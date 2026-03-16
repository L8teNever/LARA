FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn python-multipart slowapi

COPY . .

# Create uploads directory
RUN mkdir -p uploads && chmod 777 uploads

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
