from contextlib import asynccontextmanager

import logging
import os
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app import seed
from app.core.config import get_settings
from app.core.mode import current_mode
from app.routers import admin, auth, labs, legacy, orders, products, reviews, seller, users

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log = logging.getLogger("uvicorn.error")
    app.state.db_error = None
    last = None
    for attempt in range(1, 6):
        try:
            seed.run()
            last = None
            break
        except Exception as exc:  # keep the web server alive so the real cause is visible
            last = exc
            log.error("DB startup attempt %d/5 failed: %s: %s", attempt, type(exc).__name__, str(exc)[:500])
            time.sleep(3)
    if last is not None:
        app.state.db_error = f"{type(last).__name__}: {str(last)[:500]}"
        log.error("STARTUP DB ERROR (serving without database): %s", app.state.db_error)
    yield


app = FastAPI(
    title="VulnMarket API",
    version="1.0.0",
    description="Intentionally vulnerable e-commerce training API. Local training use only.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def mode_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-VulnMarket-Mode"] = current_mode()
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/api/startup-status", include_in_schema=False)
def startup_status(request: Request):
    err = getattr(request.app.state, "db_error", None)
    return {"database": "error" if err else "ok", "detail": err}


for module in (auth, users, products, orders, reviews, seller, admin, labs, legacy):
    app.include_router(module.router)


static_root = os.path.abspath(settings.static_dir)
if os.path.isdir(static_root):
    for sub in ("assets", "img"):
        folder = os.path.join(static_root, sub)
        if os.path.isdir(folder):
            app.mount(f"/{sub}", StaticFiles(directory=folder), name=sub)

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path.startswith(("api/", "legacy/", "promo/")):
            raise HTTPException(404, "Not found")
        candidate = os.path.abspath(os.path.join(static_root, full_path))
        if full_path and candidate.startswith(static_root + os.sep) and os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(os.path.join(static_root, "index.html"))
