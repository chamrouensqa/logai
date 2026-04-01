from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import require_admin
from app.models.models import User, UserRole
from app.schemas.schemas import UserCreate, UserPublic
from app.services.auth_service import hash_password

router = APIRouter(prefix="/users", tags=["Users"])


def _user_public(u: User) -> UserPublic:
    return UserPublic(
        id=u.id,
        username=u.username,
        role=u.role.value,
        created_at=u.created_at,
    )


@router.get("", response_model=list[UserPublic])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
):
    result = await db.execute(select(User).order_by(User.created_at.asc()))
    return [_user_public(u) for u in result.scalars().all()]


@router.post("", response_model=UserPublic)
async def create_user(
    data: UserCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
):
    uname = data.username.strip()
    exists = await db.execute(select(User.id).where(User.username == uname))
    if exists.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already taken")

    user = User(
        username=uname,
        password_hash=hash_password(data.password),
        role=UserRole.USER,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return _user_public(user)


@router.delete("/{user_id}")
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    if admin.id == user_id:
        raise HTTPException(status_code=400, detail="Admin cannot delete their own account")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await db.delete(user)
    await db.commit()
    return {"message": "User deleted successfully"}
