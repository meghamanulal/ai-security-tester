
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create FastAPI app
app = FastAPI(
    title="AI Security Tester - Production",
    description="Production-ready AI Security Testing Platform",
    version="1.0.0",
    docs_url=None,  # Disable docs in production
    redoc_url=None  # Disable docs in production
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "mode": "production"}

# Import and include routers
from simple_async_main import app as main_router
from pentest_api import app as orchestrator_router

# Mount routers
app.mount("/api/main", main_router)
app.mount("/api/orchestrator", orchestrator_router)

if __name__ == "__main__":
    uvicorn.run(
        "production_main:app",
        host="0.0.0.0",
        port=int(os.getenv("API_PORT", 8000)),
        workers=int(os.getenv("WORKERS", 4)),
        log_level="info"
    )
