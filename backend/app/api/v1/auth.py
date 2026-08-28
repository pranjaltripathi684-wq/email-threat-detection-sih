from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import User
from app.core.security import verify_password, get_password_hash, create_access_token, create_refresh_token, oauth2_scheme, decode_token
from app.core.audit import log_audit_event
from app.schemas.schemas import UserLogin, UserRegister, Token, UserResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse)
def register_user(user_in: UserRegister, db: Session = Depends(get_db)):
    """Registers a new user with role assignment."""
    existing = db.query(User).filter((User.username == user_in.username) | (User.email == user_in.email)).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered in system."
        )

    user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
        role=user_in.role or "Analyst"
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit_event(
        db=db,
        action="USER_REGISTERED",
        user_id=user.id,
        username=user.username,
        resource_type="User",
        resource_id=str(user.id),
        details={"role": user.role, "email": user.email}
    )

    return user


@router.post("/login", response_model=Token)
def login(login_data: UserLogin, db: Session = Depends(get_db)):
    """Authenticates user and issues signed JWT access and refresh tokens."""
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )

    access_token = create_access_token(subject=user.username, role=user.role)
    refresh_token = create_refresh_token(subject=user.username, role=user.role)

    log_audit_event(
        db=db,
        action="USER_LOGIN_SUCCESS",
        user_id=user.id,
        username=user.username,
        resource_type="Session",
        details={"role": user.role}
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "role": user.role,
        "username": user.username
    }


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Returns the authenticated user profile."""
    payload = decode_token(token)
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user
