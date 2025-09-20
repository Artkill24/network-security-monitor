from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

Base = declarative_base()

class NetworkEvent(Base):
    __tablename__ = 'network_events'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.now)
    event_type = Column(String(50))
    source_ip = Column(String(45))
    details = Column(String(500))
    severity = Column(String(20))

class DatabaseManager:
    def __init__(self, db_url="sqlite:///security_monitor.db"):
        self.engine = create_engine(db_url)
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
    
    def log_event(self, event_type, source_ip, details, severity="info"):
        event = NetworkEvent(
            event_type=event_type,
            source_ip=source_ip,
            details=str(details),
            severity=severity
        )
        self.session.add(event)
        self.session.commit()
