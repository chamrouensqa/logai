from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    pass


def _create_engine():
    is_sqlite = settings.DATABASE_URL.startswith("sqlite")
    kwargs = {"echo": settings.DEBUG}
    if not is_sqlite:
        kwargs.update(pool_size=20, max_overflow=10)
    return create_async_engine(settings.DATABASE_URL, **kwargs)


def _create_session(eng):
    return async_sessionmaker(eng, class_=AsyncSession, expire_on_commit=False)


_engine = None
_async_session = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = _create_engine()
    return _engine


def get_session_factory():
    global _async_session
    if _async_session is None:
        _async_session = _create_session(get_engine())
    return _async_session


async def get_db() -> AsyncSession:
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_ensure_schema_updates)


def _ensure_schema_updates(sync_conn):
    """Lightweight runtime schema patching for non-migration setups."""
    insp = inspect(sync_conn)
    if "analysis_jobs" not in insp.get_table_names():
        return
    columns = {c["name"] for c in insp.get_columns("analysis_jobs")}
    if "created_by_user_id" in columns:
        return
    sync_conn.execute(
        text("ALTER TABLE analysis_jobs ADD COLUMN created_by_user_id CHAR(36)")
    )


async def ensure_default_admin():
    """Create the alpha admin user when the database has no users."""
    from sqlalchemy import func, select

    from app.core.config import settings
    from app.models.models import User, UserRole
    from app.services.auth_service import hash_password

    factory = get_session_factory()
    async with factory() as db:
        n = await db.execute(select(func.count(User.id)))
        if (n.scalar() or 0) > 0:
            return
        user = User(
            username=settings.ALPHA_ADMIN_USERNAME.strip(),
            password_hash=hash_password(settings.ALPHA_ADMIN_PASSWORD),
            role=UserRole.ADMIN,
        )
        db.add(user)
        await db.commit()
