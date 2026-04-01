from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import init_db, ensure_default_admin
from app.api.routes import upload, analysis, investigation, analyze_sync, ip_reputation, auth, users_admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await ensure_default_admin()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-Powered Log Investigation Platform — Upload logs, detect threats, get AI-driven security analysis.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(users_admin.router, prefix="/api")
app.include_router(upload.router, prefix="/api")
app.include_router(analysis.router, prefix="/api")
app.include_router(investigation.router, prefix="/api")
app.include_router(analyze_sync.router, prefix="/api")
app.include_router(ip_reputation.router, prefix="/api")


@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}
