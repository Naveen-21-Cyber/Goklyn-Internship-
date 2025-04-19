# Create a new file: ip_reputation_service.py
import requests
import os
import time
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class IPReputationService:
    """
    Service for fetching IP reputation data from multiple threat intelligence sources
    """
    
    def __init__(self):
        self.virustotal_api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        self.abuseipdb_api_key = os.environ.get('ABUSEIPDB_API_KEY')
    
    def get_ip_reputation(self, ip):
        """
        Get IP reputation from multiple threat intelligence sources
        """
        # Initialize the response structure
        reputation_scores = {
            'risk_score': 0,  # 0-100, higher means more risky
            'suspicious': False,
            'blacklisted': False,
            'reports': []
        }
        
        # Try VirusTotal if API key is available
        if self.virustotal_api_key:
            virustotal_data = self._get_virustotal_data(ip)
            if virustotal_data:
                reputation_scores['reports'].append({
                    'source': 'VirusTotal',
                    'details': virustotal_data
                })
                
                # Update risk score based on VirusTotal data
                if virustotal_data['malicious'] > 0:
                    reputation_scores['suspicious'] = True
                    # Calculate risk score: 0-100 based on ratio of malicious engines
                    total_engines = virustotal_data['malicious'] + virustotal_data['harmless']
                    if total_engines > 0:
                        malicious_ratio = virustotal_data['malicious'] / total_engines
                        reputation_scores['risk_score'] = min(100, int(malicious_ratio * 100))
                        
                        # If more than 10% of engines flag it as malicious, mark as blacklisted
                        if malicious_ratio > 0.1:
                            reputation_scores['blacklisted'] = True
        
        # Try AbuseIPDB if API key is available
        if self.abuseipdb_api_key:
            abuseipdb_data = self._get_abuseipdb_data(ip)
            if abuseipdb_data:
                reputation_scores['reports'].append({
                    'source': 'AbuseIPDB',
                    'details': abuseipdb_data
                })
                
                # Update risk score based on AbuseIPDB data
                abuseipdb_score = abuseipdb_data['abuseConfidenceScore']
                # If AbuseIPDB score is higher than our current risk score, use it instead
                if abuseipdb_score > reputation_scores['risk_score']:
                    reputation_scores['risk_score'] = abuseipdb_score
                    
                # Update suspicious flag if confidence is high
                if abuseipdb_score > 50:
                    reputation_scores['suspicious'] = True
                    
                # Update blacklisted flag if confidence is very high
                if abuseipdb_score > 80:
                    reputation_scores['blacklisted'] = True
        
        # If no API data is available, fall back to the simulation logic
        if not reputation_scores['reports']:
            logger.info(f"No API data available for IP {ip}, falling back to simulation")
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
    
    def _get_virustotal_data(self, ip):
        """
        Query VirusTotal API for IP reputation
        """
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {
                "x-apikey": self.virustotal_api_key,
                "accept": "application/json"
            }
            
            logger.info(f"Querying VirusTotal API for IP: {ip}")
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                last_analysis = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                return {
                    'malicious': last_analysis.get('malicious', 0),
                    'suspicious': last_analysis.get('suspicious', 0),
                    'harmless': last_analysis.get('harmless', 0),
                    'undetected': last_analysis.get('undetected', 0),
                    'country': data.get('data', {}).get('attributes', {}).get('country', 'Unknown'),
                    'as_owner': data.get('data', {}).get('attributes', {}).get('as_owner', 'Unknown')
                }
            else:
                logger.warning(f"VirusTotal API returned status code {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"Error querying VirusTotal API: {str(e)}")
            return None
    
    def _get_abuseipdb_data(self, ip):
        """
        Query AbuseIPDB API for IP reputation
        """
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": self.abuseipdb_api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True
            }
            
            logger.info(f"Querying AbuseIPDB API for IP: {ip}")
            response = requests.get(url, headers=headers, params=params, timeout=5)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                return {
                    'abuseConfidenceScore': data.get('abuseConfidenceScore', 0),
                    'totalReports': data.get('totalReports', 0),
                    'countryCode': data.get('countryCode', 'Unknown'),
                    'usageType': data.get('usageType', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'domain': data.get('domain', 'Unknown'),
                    'lastReportedAt': data.get('lastReportedAt', None)
                }
            else:
                logger.warning(f"AbuseIPDB API returned status code {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"Error querying AbuseIPDB API: {str(e)}")
            return None