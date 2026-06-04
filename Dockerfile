FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn python-multipart slowapi clamd

COPY . .

# Create uploads directory
RUN mkdir -p uploads && chmod 777 uploads

EXPOSE 8000

RUN chmod +x start.sh

CMD ["bash", "start.sh"]
