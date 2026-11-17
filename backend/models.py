from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="Viewer") # Admin, Operator, Viewer, Guest
    permissions = Column(String, default="read") # read, write, admin
    is_active = Column(Boolean, default=True)

class Node(Base):
    __tablename__ = "nodes"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    hostname = Column(String, nullable=True)
    mac_address = Column(String, nullable=True)
    wifi_mac = Column(String, nullable=True)
    ether_mac = Column(String, nullable=True)
    system_mac = Column(String, nullable=True)
    status = Column(String, default="offline") # online, offline
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    logout_time = Column(DateTime, nullable=True)
    is_monitored = Column(Boolean, default=False)
    last_alert_at = Column(DateTime, nullable=True)

    metrics = relationship("Metric", back_populates="node")
    alerts = relationship("Alert", back_populates="node")

class Metric(Base):
    __tablename__ = "metrics"
    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(Integer, ForeignKey("nodes.id"))
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    disk_usage = Column(Float)
    disk_total_gb = Column(Float, default=0)
    disk_used_gb = Column(Float, default=0)
    disk_free_gb = Column(Float, default=0)
    network_sent = Column(Float)
    network_recv = Column(Float)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    node = relationship("Node", back_populates="metrics")

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(Integer, ForeignKey("nodes.id"))
    alert_type = Column(String) # CPU, Memory, Disk
    message = Column(String)
    severity = Column(String) # Warning, Critical
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    is_resolved = Column(Boolean, default=False)

    node = relationship("Node", back_populates="alerts")
class DiscoveredHost(Base):
    __tablename__ = "discovered_hosts"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    hostname = Column(String, nullable=True)
    subnet = Column(String)
    mac_address = Column(String, nullable=True)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    agent_installed = Column(Boolean, default=False)

class MonitoredServer(Base):
    __tablename__ = "monitored_servers"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    subnet = Column(String)
    monitoring_enabled = Column(Boolean, default=True)
    agent_status = Column(String, default="offline")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class WebsiteMonitor(Base):
    __tablename__ = "website_monitors"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True)
    status = Column(String, default="DOWN") # UP, DOWN
    response_time = Column(Float, nullable=True)
    last_checked = Column(DateTime, default=datetime.datetime.utcnow)

class Fail2BanStatus(Base):
    __tablename__ = "fail2ban_status"
    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(Integer, ForeignKey("nodes.id"))
    jail_name = Column(String)
    currently_failed = Column(Integer)
    total_failed = Column(Integer)
    currently_banned = Column(Integer)
    total_banned = Column(Integer)
    banned_ips = Column(String) # Comma-separated or JSON
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    node = relationship("Node", backref="fail2ban_stats")

