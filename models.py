# models.py - Database models
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Website(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    ip = db.Column(db.String(45), nullable=False)  # IPv6 can be up to 45 chars
    domain = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    scan_results = db.relationship('ScanResult', backref='website', lazy=True)
    
    def __repr__(self):
        return f'<Website {self.domain}>'

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False)
    risk_level = db.Column(db.String(10), nullable=False)  # Low, Medium, High
    risk_score = db.Column(db.Integer, nullable=False)  # 0-100
    open_ports = db.Column(db.Text, nullable=False)  # JSON string of open ports
    reputation = db.Column(db.String(20), nullable=False)  # Good, Suspicious
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    recommendations = db.relationship('Recommendation', backref='scan_result', lazy=True)
    alerts = db.relationship('Alert', backref='scan_result', lazy=True)
    
    def __repr__(self):
        return f'<ScanResult {self.id} for Website {self.website_id}>'

class Recommendation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    
    def __repr__(self):
        return f'<Recommendation {self.id} for ScanResult {self.scan_result_id}>'

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=False)
    severity = db.Column(db.String(10), nullable=False)  # Low, Medium, High
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Alert {self.id} for ScanResult {self.scan_result_id}>'