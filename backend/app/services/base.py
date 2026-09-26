"""
NYAYAI - Base Service Class
Module: backend.app.services.base
"""

from sqlalchemy.orm import Session
from backend.app.utils.logger import get_logger


class BaseService:
    def __init__(self, db: Session):
        self.db = db
        self.logger = get_logger(self.__class__.__name__)
