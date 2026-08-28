from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Any, List
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")


class Role:
    ANALYST = "Analyst"
    ADMINISTRATOR = "Administrator"
    INVESTIGATOR = "Investigator"
    AUDITOR = "Auditor"
    ALL_ROLES = [ANALYST, ADMINISTRATOR, INVESTIGATOR, AUDITOR]


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(subject: Union[str, Any], role: str, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {
        "sub": str(subject),
        "role": role,
        "exp": expire,
        "type": "access"
    }
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(subject: Union[str, Any], role: str, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
        
    to_encode = {
        "sub": str(subject),
        "role": role,
        "exp": expire,
        "type": "refresh"
    }
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_roles(allowed_roles: List[str]):
    def role_checker(token: str = Depends(oauth2_scheme)):
        payload = decode_token(token)
        user_role = payload.get("role")
        if not user_role or user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Required roles: {allowed_roles}, your role: {user_role}"
            )
        return payload
    return role_checker


def mask_email(email: str, mask_enabled: bool = True) -> str:
    """Mask email address for privacy preservation (e.g. j***@example.com)"""
    if not mask_enabled or not email or "@" not in email:
        return email
    try:
        local_part, domain = email.split("@", 1)
        if len(local_part) <= 2:
            masked_local = local_part[0] + "***"
        else:
            masked_local = local_part[0] + "***" + local_part[-1]
        return f"{masked_local}@{domain}"
    except Exception:
        return email
