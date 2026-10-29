"""Main FastAPI Application Entrypoint for FirewallLang."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router

app = FastAPI(
    title="FirewallLang Compiler API",
    description="Domain-Specific Language (DSL) Compiler and Static Misconfiguration Analyzer for Network Firewall Policies.",
    version="1.0.0",
)

# CORS configuration restricted to local dev environments
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
def root():
    return {
        "service": "FirewallLang Compiler Backend",
        "docs_url": "/docs",
        "health_url": "/health",
        "status": "operational",
    }
