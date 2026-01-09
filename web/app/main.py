from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles 
import logging
import uvicorn
import os
import time

from .routes import router, log_requests
from .database import initialize_database_with_data, query_database
from .config import DB_SERVER_HOST, DB_SERVER_PORT, SECURITY_DB, SECURITY_COLLECTION

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SIEM Web Interface",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.middleware("http")(log_requests)

app.mount("/css", StaticFiles(directory="frontend/css"), name="css")
app.mount("/js", StaticFiles(directory="frontend/js"), name="js")
app.mount("/static", StaticFiles(directory="frontend"), name="static")

app.include_router(router)

@app.on_event("startup")
async def startup_event():
    """Инициализация базы данных при старте приложения"""
    logger.info("=" * 50)
    logger.info("SIEM Web Server Starting...")
    logger.info(f"Database: {DB_SERVER_HOST}:{DB_SERVER_PORT}")
    logger.info(f"Security DB: {SECURITY_DB}.{SECURITY_COLLECTION}")
    logger.info("=" * 50)
    
    # Ждем, пока база данных станет доступна
    max_retries = 10
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            logger.info(f"Testing database connection (attempt {attempt + 1}/{max_retries})...")
            test_response = query_database("find", SECURITY_COLLECTION, {})
            
            if test_response.get('status') == 'error':
                error_message = test_response.get('message', '')
                
                # Если база данных не найдена, создаем её через INSERT
                if 'Database not found' in error_message or 'not found' in error_message.lower():
                    logger.info("Database does not exist, initializing with test data...")
                    initialize_database_with_data()
                    # Проверяем еще раз после инициализации
                    time.sleep(1)
                    test_response = query_database("find", SECURITY_COLLECTION, {})
                    if test_response.get('status') == 'success':
                        event_count = test_response.get('count', 0)
                        logger.info(f"Database initialized successfully, found {event_count} events")
                        break
                    else:
                        logger.warning("Database initialization may have failed, retrying...")
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay)
                            continue
                elif 'not running' in error_message.lower() or 'Connection' in error_message:
                    # Проблема с подключением к серверу БД
                    if attempt < max_retries - 1:
                        logger.warning(f"Database server not ready yet, retrying in {retry_delay}s...")
                        time.sleep(retry_delay)
                        continue
                    else:
                        logger.error(f"Database connection failed: {error_message}")
                        logger.error(f"Please ensure db_server is running on port {DB_SERVER_PORT}")
                        return
                else:
                    # Другая ошибка
                    if attempt < max_retries - 1:
                        logger.warning(f"Database error: {error_message}, retrying in {retry_delay}s...")
                        time.sleep(retry_delay)
                        continue
                    else:
                        logger.error(f"Database connection failed: {error_message}")
                        return
            else:
                # Успешное подключение
                event_count = test_response.get('count', 0)
                logger.info(f"Database connection OK, found {event_count} events")
                
                # Если база данных пустая, инициализируем тестовыми данными
                if event_count == 0:
                    logger.info("Database is empty, initializing with test data...")
                    initialize_database_with_data()
                    logger.info("Test data initialization completed")
                else:
                    logger.info(f"Database already contains {event_count} events")
                break
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"Connection attempt failed: {e}, retrying in {retry_delay}s...")
                time.sleep(retry_delay)
            else:
                logger.error(f"Failed to connect to database after {max_retries} attempts: {e}")

if __name__ == "__main__":
    print("=" * 50)
    print("SIEM Web Server Starting...")
    print(f"Database: {DB_SERVER_HOST}:{DB_SERVER_PORT}")
    print(f"Security DB: {SECURITY_DB}.{SECURITY_COLLECTION}")
    print(f"Web Interface: http://localhost:8000")
    print("=" * 50)

    from .database import query_database
    print("Testing database connection...")
    test_response = query_database("find", SECURITY_COLLECTION, {})

    if test_response.get('status') == 'error':
        print(f"WARNING: Database connection failed: {test_response.get('message')}")
        print(f"Please ensure db_server is running on port {DB_SERVER_PORT}")
    else:
        event_count = test_response.get('count', 0)
        print(f"Database connection OK, found {event_count} events")

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        reload=False
    )