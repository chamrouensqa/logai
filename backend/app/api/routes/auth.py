from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import User
from app.schemas.schemas import ChangePasswordRequest, LoginRequest, TokenResponse, UserPublic
from app.services.auth_service import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["Auth"])


def _user_public(u: User) -> UserPublic:
    return UserPublic(
        id=u.id,
        username=u.username,
        role=u.role.value,
        created_at=u.created_at,
    )


@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == data.username.strip()))
    user = result.scalar_one_or_none()
    if not user or not user.is_active or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_access_token(user.id, user.role.value)
    return TokenResponse(access_token=token, user=_user_public(user))


@router.get("/me", response_model=UserPublic)
async def me(current: User = Depends(get_current_user)):
    return _user_public(current)


@router.post("/change-password")
async def change_password(
    data: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    current: User = Depends(get_current_user),
):
    if not verify_password(data.current_password, current.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if data.current_password == data.new_password:
        raise HTTPException(status_code=400, detail="New password must be different")

    current.password_hash = hash_password(data.new_password)
    db.add(current)
    await db.commit()
    return {"message": "Password updated successfully"}
