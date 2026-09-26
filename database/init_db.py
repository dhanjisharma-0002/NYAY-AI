"""
NYAYAI - Database Initialization & Seed Utility (Phase 3)
Module: database.init_db
Seeds:
- Standard roles: ADMIN, INVESTIGATOR, LAWYER, JUDGE (and backward-compatible roles)
- Default administrative and investigative users with secure bcrypt hashes
"""

import sys
import os
import uuid

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy import text
from database.connection import engine, Base, SessionLocal
from database.models import User, Role
from backend.app.core.security import get_password_hash


def init_database():
    print("[NYAYAI] Initializing database tables...")
    Base.metadata.create_all(bind=engine)
    
    # Auto-migrate SQLite columns if table was created previously
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE analysis_results ADD COLUMN explanation VARCHAR(1024)"))
            conn.commit()
        except Exception:
            pass # Column already exists or table freshly created
            
    print("[NYAYAI] Tables created successfully.")

    db = SessionLocal()
    try:
        # 1. Seed Core Supported Roles (ADMIN, INVESTIGATOR, LAWYER, JUDGE)
        roles_data = [
            ("ADMIN", "Full administrative control, user management, and system configuration", ["*"]),
            ("INVESTIGATOR", "Case management, evidence intake, and analysis triggers", ["case:create", "case:read", "case:update", "evidence:upload", "evidence:read", "analysis:initiate"]),
            ("LAWYER", "Permitted case inspection and legal report viewing", ["case:view_permitted", "reports:view"]),
            ("JUDGE", "Judicial review, authenticity sealing, and custody verification", ["case:read", "reports:view", "reports:verify_authenticity", "custody:verify"]),
            # Legacy roles from Phase 0-2
            ("SYSTEM_LEAD", "Legacy administrative orchestrator role", ["*"]),
            ("FORENSIC_EXPERT", "Deep forensic inspection and AI screening verification", ["forensics:inspect", "ai:screen", "reports:generate"]),
            ("AUDITOR", "Read-only access to chain of custody and audit logs", ["custody:read", "audit:read", "verification:verify"])
        ]

        seeded_roles = {}
        for role_name, description, permissions in roles_data:
            existing_role = db.query(Role).filter_by(name=role_name).first()
            if not existing_role:
                new_role = Role(
                    id=str(uuid.uuid4()),
                    name=role_name,
                    description=description,
                    permissions=permissions
                )
                db.add(new_role)
                db.flush()
                seeded_roles[role_name] = new_role
            else:
                seeded_roles[role_name] = existing_role

        # 2. Seed Baseline Admin & Investigator Users with secure bcrypt hash
        default_pwd_hash = get_password_hash("SecureNyayPassword2026!")

        admin_user = db.query(User).filter_by(username="admin_nyay").first()
        if not admin_user:
            admin_role = seeded_roles.get("ADMIN")
            admin_user = User(
                id=str(uuid.uuid4()),
                username="admin_nyay",
                email="admin@nyayai.gov.in",
                hashed_password=default_pwd_hash,
                full_name="Chief System Administrator",
                badge_number="ADM-DL-001",
                role_id=admin_role.id if admin_role else None,
                role="ADMIN",
                is_active=True
            )
            db.add(admin_user)
            print("[NYAYAI] Default admin seeded: admin_nyay")

        existing_user = db.query(User).filter_by(username="investigator_dhananjay").first()
        if not existing_user:
            lead_role = seeded_roles.get("SYSTEM_LEAD")
            lead_user = User(
                id=str(uuid.uuid4()),
                username="investigator_dhananjay",
                email="dhananjay@nyayai.gov.in",
                hashed_password=default_pwd_hash,
                full_name="Dhananjay Sharma",
                badge_number="INV-DL-9841",
                role_id=lead_role.id if lead_role else None,
                role="INVESTIGATOR",
                is_active=True
            )
            db.add(lead_user)
            print("[NYAYAI] Default investigator seeded: investigator_dhananjay")
        else:
            # Update password hash if legacy placeholder was used
            if existing_user.hashed_password.startswith("pbkdf2:"):
                existing_user.hashed_password = default_pwd_hash
                print("[NYAYAI] Upgraded investigator_dhananjay to secure bcrypt hash.")

        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    init_database()
