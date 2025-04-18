# app.py - Main Flask application
from flask import Flask

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import threading
import time
from datetime import datetime
import json
import validators
import socket
import requests
import whois
import nmap
from models import db, Website, ScanResult, Alert, Recommendation
from ml_models import risk_analyzer, anomaly_detector

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybersecurity.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
CORS(app)  # Enable CORS for all routes

# Initialize the database
db.init_app(app)



# Utility functions
def is_valid_url(url):
    return validators.url(url)

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def get_ip_reputation(ip):
    # This would normally use an API like VirusTotal or AbuseIPDB
    # For demo purposes, simulating a reputation API call
    reputation_scores = {
        'risk_score': 0,  # 0-100, higher means more risky
        'suspicious': False,
        'blacklisted': False,
        'reports': []
    }
    
    # Simulate API call delay
    time.sleep(0.5)
    
    # Simulate risk based on IP patterns (purely for demo)
    if ip.startswith('10.') or ip.startswith('192.168.'):
        reputation_scores['risk_score'] = 10
    elif ip.endswith('.100') or ip.endswith('.200'):
        reputation_scores['risk_score'] = 55
        reputation_scores['suspicious'] = True
    elif ip.endswith('.1') or ip.endswith('.254'):
        reputation_scores['risk_score'] = 25
    else:
        # Random moderate risk
        reputation_scores['risk_score'] = 30
    
    return reputation_scores

def scan_ports(ip):
    # This would normally use nmap or similar tool
    # For demo, we'll simulate port scanning
    nm = nmap.PortScanner()
    try:
        # Scan common ports
        nm.scan(ip, '21-23,25,53,80,443,3306,8080')
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append(port)
        return open_ports
    except:
        # If there's an error or in development, return simulated ports
        simulated_ports = [22, 80, 443]
        if sum(map(int, ip.split('.'))) % 2 == 0:
            simulated_ports.append(8080)
        if sum(map(int, ip.split('.'))) % 3 == 0:
            simulated_ports.append(3306)
        return simulated_ports

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'last_updated': w.updated_date,
            'name_servers': w.name_servers
        }
    except:
        # Return mock data if there's an error
        return {
            'registrar': 'Example Registrar LLC',
            'creation_date': '2020-01-01',
            'expiration_date': '2025-01-01',
            'last_updated': '2023-01-01',
            'name_servers': ['ns1.example.com', 'ns2.example.com']
        }

def get_ssl_info(url):
    if not url.startswith('http'):
        url = 'https://' + url
    
    try:
        response = requests.get(url, timeout=3)
        has_ssl = response.url.startswith('https')
        
        ssl_info = {
            'has_ssl': has_ssl,
            'cert_valid': response.status_code != 495,
            'redirect_to_https': response.url.startswith('https') and not url.startswith('https'),
            'hsts': 'Strict-Transport-Security' in response.headers,
        }
        return ssl_info
    except:
        # Return mock data if there's an error
        return {
            'has_ssl': url.startswith('https'),
            'cert_valid': True,
            'redirect_to_https': False,
            'hsts': False,
        }

def generate_risk_data(domain, ip, url):
    # This function would use our ML models to analyze the security posture
    # For now, we'll simulate this with some rules
    
    # Get reputation data
    reputation = get_ip_reputation(ip)
    
    # Get port data
    open_ports = scan_ports(ip)
    
    # Get SSL info
    ssl_info = get_ssl_info(url)
    
    # Calculate risk score (0-100)
    risk_score = reputation['risk_score']
    
    # Adjust score based on ports
    if 22 in open_ports:
        risk_score += 5
    if 3306 in open_ports:
        risk_score += 10
    if 8080 in open_ports:
        risk_score += 15
    
    # Adjust score based on SSL
    if not ssl_info['has_ssl']:
        risk_score += 30
    elif not ssl_info['cert_valid']:
        risk_score += 20
    elif not ssl_info['hsts']:
        risk_score += 10
        
    # Cap at 100
    risk_score = min(risk_score, 100)
    
    # Determine risk level
    if risk_score >= 70:
        risk_level = 'High'
    elif risk_score >= 40:
        risk_level = 'Medium'
    else:
        risk_level = 'Low'
    
    # Generate recommendations
    recommendations = []
    
    if not ssl_info['has_ssl']:
        recommendations.append('Implement SSL/TLS encryption')
    elif not ssl_info['cert_valid']:
        recommendations.append('Fix SSL certificate issues')
    elif not ssl_info['hsts']:
        recommendations.append('Enable HTTP Strict Transport Security (HSTS)')
    
    if 8080 in open_ports:
        recommendations.append('Close unused port 8080')
    if 3306 in open_ports:
        recommendations.append('Secure MySQL port (3306) or close if not needed')
    
    # Always add these general recommendations
    recommendations.append('Enable Web Application Firewall (WAF)')
    recommendations.append('Implement rate limiting on login endpoints')
    
    # Generate historical data for charts
    historical_data = []
    base_risk = max(30, risk_score - 20)
    
    for i in range(7):
        day_risk = base_risk + (i * 3)  # Gradually increasing risk
        if day_risk > 100:
            day_risk = 100
        historical_data.append(day_risk)
    
    # Put together response
    result = {
        'risk_level': risk_level,
        'risk_score': risk_score,
        'open_ports': open_ports,
        'reputation': 'Suspicious' if reputation['suspicious'] else 'Good',
        'recommendations': recommendations,
        'historical_data': historical_data,
        'ssl_info': ssl_info,
        'whois': get_whois_info(domain),
        'last_updated': datetime.now().isoformat()
    }
    
    return result

def schedule_scan(website_id):
    """Run a scan in the background"""
    def run_scan():
        with app.app_context():
            website = Website.query.get(website_id)
            if not website:
                return
                
            # Get the scan results
            result = generate_risk_data(website.domain, website.ip, website.url)
            
            # Save the scan results
            scan_result = ScanResult(
                website_id=website.id,
                risk_level=result['risk_level'],
                risk_score=result['risk_score'],
                open_ports=json.dumps(result['open_ports']),
                reputation=result['reputation'],
                scan_date=datetime.now()
            )
            db.session.add(scan_result)
            
            # Save the recommendations
            for rec in result['recommendations']:
                recommendation = Recommendation(
                    scan_result_id=scan_result.id,
                    text=rec
                )
                db.session.add(recommendation)
                
            db.session.commit()
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    return True

# API Routes
@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    
    # Validate inputs
    url = data.get('url', '')
    ip = data.get('ip', '')
    domain = data.get('domain', '')
    
    errors = {}
    if not url or not is_valid_url(url):
        errors['url'] = 'Please enter a valid URL'
    if not ip or not is_valid_ip(ip):
        errors['ip'] = 'Please enter a valid IP address'
    if not domain:
        errors['domain'] = 'Domain is required'
        
    if errors:
        return jsonify({'status': 'error', 'errors': errors}), 400
    
    # Save website to database
    website = Website.query.filter_by(domain=domain).first()
    if not website:
        website = Website(url=url, ip=ip, domain=domain)
        db.session.add(website)
        db.session.commit()
    else:
        # Update existing website info
        website.url = url
        website.ip = ip
        db.session.commit()
    
    # Generate risk data
    result = generate_risk_data(domain, ip, url)
    
    # Save the scan results
    scan_result = ScanResult(
        website_id=website.id,
        risk_level=result['risk_level'],
        risk_score=result['risk_score'],
        open_ports=json.dumps(result['open_ports']),
        reputation=result['reputation'],
        scan_date=datetime.now()
    )
    db.session.add(scan_result)
    db.session.commit()
    
    # Save the recommendations
    for rec in result['recommendations']:
        recommendation = Recommendation(
            scan_result_id=scan_result.id,
            text=rec
        )
        db.session.add(recommendation)
    
    db.session.commit()
    
    # Schedule a background scan for more detailed analysis
    schedule_scan(website.id)
    
    return jsonify({
        'status': 'success',
        'result': result
    })

@app.route('/api/websites', methods=['GET'])
def get_websites():
    websites = Website.query.all()
    return jsonify({
        'status': 'success',
        'websites': [
            {
                'id': website.id,
                'url': website.url,
                'ip': website.ip,
                'domain': website.domain,
                'created_at': website.created_at.isoformat()
            }
            for website in websites
        ]
    })

@app.route('/api/website/<int:website_id>', methods=['GET'])
def get_website(website_id):
    website = Website.query.get_or_404(website_id)
    
    # Get latest scan result
    latest_scan = ScanResult.query.filter_by(website_id=website_id).order_by(ScanResult.scan_date.desc()).first()
    
    if latest_scan:
        # Get recommendations for this scan
        recommendations = Recommendation.query.filter_by(scan_result_id=latest_scan.id).all()
        
        result = {
            'website': {
                'id': website.id,
                'url': website.url,
                'ip': website.ip,
                'domain': website.domain,
                'created_at': website.created_at.isoformat()
            },
            'scan_result': {
                'id': latest_scan.id,
                'risk_level': latest_scan.risk_level,
                'risk_score': latest_scan.risk_score,
                'open_ports': json.loads(latest_scan.open_ports),
                'reputation': latest_scan.reputation,
                'scan_date': latest_scan.scan_date.isoformat(),
                'recommendations': [rec.text for rec in recommendations]
            }
        }
    else:
        result = {
            'website': {
                'id': website.id,
                'url': website.url,
                'ip': website.ip,
                'domain': website.domain,
                'created_at': website.created_at.isoformat()
            },
            'scan_result': None
        }
    
    return jsonify({
        'status': 'success',
        'data': result
    })

@app.route('/api/scan_history/<int:website_id>', methods=['GET'])
def get_scan_history(website_id):
    # Check if website exists
    website = Website.query.get_or_404(website_id)
    
    # Get scan history
    scans = ScanResult.query.filter_by(website_id=website_id).order_by(ScanResult.scan_date.desc()).all()
    
    scan_history = []
    for scan in scans:
        # Get recommendations for this scan
        recommendations = Recommendation.query.filter_by(scan_result_id=scan.id).all()
        
        scan_history.append({
            'id': scan.id,
            'risk_level': scan.risk_level,
            'risk_score': scan.risk_score,
            'open_ports': json.loads(scan.open_ports),
            'reputation': scan.reputation,
            'scan_date': scan.scan_date.isoformat(),
            'recommendations': [rec.text for rec in recommendations]
        })
    
    return jsonify({
        'status': 'success',
        'website': {
            'id': website.id,
            'url': website.url,
            'ip': website.ip,
            'domain': website.domain
        },
        'scan_history': scan_history
    })

@app.route('/api/rescan/<int:website_id>', methods=['POST'])
def rescan_website(website_id):
    # Check if website exists
    website = Website.query.get_or_404(website_id)
    
    # Generate risk data
    result = generate_risk_data(website.domain, website.ip, website.url)
    
    # Save the scan results
    scan_result = ScanResult(
        website_id=website.id,
        risk_level=result['risk_level'],
        risk_score=result['risk_score'],
        open_ports=json.dumps(result['open_ports']),
        reputation=result['reputation'],
        scan_date=datetime.now()
    )
    db.session.add(scan_result)
    db.session.commit()
    
    # Save the recommendations
    for rec in result['recommendations']:
        recommendation = Recommendation(
            scan_result_id=scan_result.id,
            text=rec
        )
        db.session.add(recommendation)
    
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'result': result
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)