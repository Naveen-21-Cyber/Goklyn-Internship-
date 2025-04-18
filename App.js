import React, { useState } from 'react';
import { Shield, AlertTriangle, Activity, Server, Lock, Globe, Database, X } from 'lucide-react';
import './App.css'; 

export default function App() {
  const [scanResult, setScanResult] = useState(null);
  const [recommendations, setRecommendations] = useState([]);
  const [riskData, setRiskData] = useState({
    labels: ['Last Week', '6 Days Ago', '5 Days Ago', '4 Days Ago', '3 Days Ago', '2 Days Ago', 'Yesterday'],
    values: [35, 42, 38, 45, 40, 48, 52]
  });
  const [loading, setLoading] = useState(false);
  const [scanCompleted, setScanCompleted] = useState(false);
  

  // Update the handleScan function in App.js
const handleScan = async (formData) => {
  setLoading(true);
  
  try {
    const response = await fetch('http://localhost:5000/api/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(formData),
    });
    
    const data = await response.json();
    
    if (data.status === 'success') {
      setScanResult({
        risk: data.result.risk_level,
        openPorts: data.result.open_ports,
        reputation: data.result.reputation,
        lastUpdated: new Date().toLocaleString()
      });
      
      setRecommendations(data.result.recommendations);
      
      setRiskData({
        labels: ['Last Week', '6 Days Ago', '5 Days Ago', '4 Days Ago', '3 Days Ago', '2 Days Ago', 'Yesterday'],
        values: data.result.historical_data
      });
      
      setScanCompleted(true);
    } else {
      // Handle errors
      console.error('Scan failed:', data.errors);
      alert('Scan failed: ' + JSON.stringify(data.errors));
    }
  } catch (error) {
    console.error('Error during scan:', error);
    alert('Error during scan. Please try again.');
  } finally {
    setLoading(false);
  }
};

  return (
    <div className="app-container">
      {/* Header */}
      <header className="app-header">
        <div className="container">
          <Home />
        </div>
      </header>
      
      {/* Main Content */}
      <main>
        <div className="container">
          {/* Scan Form */}
          <div className="card">
            <ScanForm onScan={handleScan} loading={loading} />
          </div>
          
          {/* Results Grid */}
          <div className="results-grid">
            {/* Dashboard */}
            <div className="card">
              <Dashboard results={scanResult} loading={loading} scanCompleted={scanCompleted} />
            </div>
            
            {/* Alerts */}
            <div className="card">
              <Alerts recommendations={recommendations} scanCompleted={scanCompleted} loading={loading} />
            </div>
            
            {/* Security Score */}
            <div className="card">
              <SecurityScore result={scanResult} scanCompleted={scanCompleted} loading={loading} />
            </div>
            
            {/* Risk Chart - Full Width */}
            <div className="card chart-container">
              <RiskChart riskData={riskData} scanCompleted={scanCompleted} loading={loading} />
            </div>
          </div>
        </div>
      </main>
      
      {/* Footer */}
      <footer className="app-footer">
        <div className="container">
          <p>© 2025 AI-Powered Cybersecurity Incident Predictor | Privacy Policy | Terms of Service</p>
        </div>
      </footer>
    </div>
  );
}

function Home() {
  return (
    <div className="text-center">
      <h1 className="text-4xl font-bold mb-4">AI-Powered Cybersecurity Incident Predictor</h1>
      <p className="mb-8">Get real-time threat analysis and actionable recommendations for your web assets</p>
      <div className="flex flex-wrap justify-center gap-4">
        <div className="status-indicator">
          <Shield className="mr-2" size={20} />
          <span>Deep Scanning</span>
        </div>
        <div className="status-indicator">
          <AlertTriangle className="mr-2" size={20} />
          <span>Threat Intelligence</span>
        </div>
        <div className="status-indicator">
          <Activity className="mr-2" size={20} />
          <span>Risk Analytics</span>
        </div>
      </div>
    </div>
  );
}


function ScanForm({ onScan, loading }) {
  const [formData, setFormData] = useState({ url: '', ip: '', domain: '' });
  const [errors, setErrors] = useState({});

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.url) {
      newErrors.url = 'URL is required';
    } else if (!/^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*\/?$/.test(formData.url)) {
      newErrors.url = 'Please enter a valid URL';
    }
    
    if (!formData.ip) {
      newErrors.ip = 'IP is required';
    } else if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(formData.ip)) {
      newErrors.ip = 'Please enter a valid IP address';
    }
    
    if (!formData.domain) {
      newErrors.domain = 'Domain is required';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    if (errors[e.target.name]) {
      setErrors({ ...errors, [e.target.name]: null });
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (validateForm()) {
      onScan(formData);
    }
  };

  return (
    <div>
      <div className="card-header">
        <h2 className="card-title">Scan Your Website</h2>
      </div>
      
      <form onSubmit={handleSubmit} className="scan-form-grid">
        <div className="form-group">
          <label htmlFor="url">Website URL</label>
          <div className="relative">
            <Globe size={18} className="form-icon" />
            <input 
              type="text" 
              id="url"
              name="url" 
              className="form-control" 
              placeholder="https://example.com" 
              value={formData.url}
              onChange={handleChange} 
            />
          </div>
          {errors.url && <div className="error-message">{errors.url}</div>}
        </div>
        
        <div className="form-group">
          <label htmlFor="ip">Server IP</label>
          <div className="relative">
            <Server size={18} className="form-icon" />
            <input 
              type="text" 
              id="ip"
              name="ip" 
              className="form-control" 
              placeholder="192.168.1.1" 
              value={formData.ip}
              onChange={handleChange} 
            />
          </div>
          {errors.ip && <div className="error-message">{errors.ip}</div>}
        </div>
        
        <div className="form-group">
          <label htmlFor="domain">Domain Name</label>
          <div className="relative">
            <Database size={18} className="form-icon" />
            <input 
              type="text" 
              id="domain"
              name="domain" 
              className="form-control" 
              placeholder="example.com" 
              value={formData.domain}
              onChange={handleChange} 
            />
          </div>
          {errors.domain && <div className="error-message">{errors.domain}</div>}
        </div>
        
        <button 
          type="submit" 
          className="btn btn-primary btn-full" 
          disabled={loading}
        >
          {loading ? (
            <>
              <div className="loading-spinner"></div>
              <span>Scanning...</span>
            </>
          ) : (
            'Scan Now'
          )}
        </button>
      </form>
    </div>
  );
}

function Dashboard({ results, loading, scanCompleted }) {
  const getRiskClass = (risk) => {
    switch(risk?.toLowerCase()) {
      case 'high':
        return 'status-high';
      case 'medium':
        return 'status-medium';
      case 'low':
        return 'status-low';
      default:
        return '';
    }
  };
  
  return (
    <div>
      <div className="card-header">
        <h2 className="card-title">Scan Results</h2>
      </div>
      
      {loading ? (
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Analyzing security posture...</p>
        </div>
      ) : results && scanCompleted ? (
        <div className="results-container">
          <div className="result-item">
            <div className="result-label">Risk Level</div>
            <div className={`status-indicator ${getRiskClass(results.risk)}`}>
              {results.risk}
            </div>
          </div>
          
          <div className="result-item">
            <h3>Open Ports</h3>
            <div className="ports-list">
              {results.openPorts.map((port, i) => (
                <span key={i} className="port-tag">
                  <Server size={14} className="port-icon" />
                  {port}
                </span>
              ))}
            </div>
          </div>
          
          <div className="result-item">
            <h3>IP Reputation</h3>
            <div className="reputation-value">
              {results.reputation === 'Suspicious' ? (
                <span className="reputation-suspicious">{results.reputation}</span>
              ) : (
                <span className="reputation-good">{results.reputation}</span>
              )}
            </div>
          </div>
          
          <div className="result-updated">
            Last updated: {results.lastUpdated}
          </div>
        </div>
      ) : (
        <div className="empty-state">
          <p>No scan results yet. Submit a scan to analyze your security posture.</p>
        </div>
      )}
    </div>
  );
}

function Alerts({ recommendations, scanCompleted, loading }) {
  const getRecommendationIcon = (rec) => {
    if (rec.toLowerCase().includes('port')) return <Server size={16} className="rec-icon port" />;
    if (rec.toLowerCase().includes('ssl') || rec.toLowerCase().includes('https')) return <Lock size={16} className="rec-icon ssl" />;
    if (rec.toLowerCase().includes('waf')) return <Shield size={16} className="rec-icon waf" />;
    if (rec.toLowerCase().includes('rate')) return <Activity size={16} className="rec-icon rate" />;
    return <X size={16} className="rec-icon other" />;
  };

  return (
    <div>
      <div className="card-header">
        <h2 className="card-title">Security Recommendations</h2>
      </div>
      
      {loading ? (
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Generating recommendations...</p>
        </div>
      ) : recommendations && recommendations.length > 0 && scanCompleted ? (
        <div className="recommendations-list">
          {recommendations.map((rec, i) => (
            <div key={i} className="recommendation-item">
              {getRecommendationIcon(rec)}
              <div className="recommendation-text">{rec}</div>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-state">
          <p>No recommendations available. Run a scan to get security insights.</p>
        </div>
      )}
    </div>
  );
}

function SecurityScore({ result, scanCompleted, loading }) {
  const getScore = () => {
    if (!result) return 0;
    
    switch(result.risk) {
      case 'Low': return 85;
      case 'Medium': return 65;
      case 'High': return 40;
      default: return 0;
    }
  };
  
  const score = getScore();
  
  const getScoreColor = () => {
    if (score >= 80) return 'score-high';
    if (score >= 60) return 'score-medium';
    return 'score-low';
  };
  
  const getDescription = () => {
    if (score >= 80) return 'Good security posture';
    if (score >= 60) return 'Needs improvement';
    return 'Critical issues found';
  };

  return (
    <div>
      <div className="card-header">
        <h2 className="card-title">Security Score</h2>
      </div>
      
      {loading ? (
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Calculating score...</p>
        </div>
      ) : result && scanCompleted ? (
        <div className="score-container">
          <div className={`score-value ${getScoreColor()}`}>
            {score}/100
          </div>
          <div className={`score-label ${getScoreColor()}`}>
            {getDescription()}
          </div>
          
          <div className="score-bar-container">
            <div 
              className={`score-bar ${getScoreColor()}`} 
              style={{ width: `${score}%` }}>
            </div>
          </div>
          
          <div className="score-legend">
            <span>Critical</span>
            <span>Moderate</span>
            <span>Secure</span>
          </div>
        </div>
      ) : (
        <div className="empty-state">
          <p>No security score yet. Run a scan to get your security rating.</p>
        </div>
      )}
    </div>
  );
}

function RiskChart({ riskData, scanCompleted, loading }) {
  // Calculate max value for chart scaling
  const maxValue = Math.max(...riskData.values) + 10;

  // Create SVG path for the chart line
  const createPath = () => {
    const height = 200;
    const width = 700;
    const padding = 30;
    const availableHeight = height - (padding * 2);
    const availableWidth = width - (padding * 2);
    
    const xStep = availableWidth / (riskData.values.length - 1);
    
    const points = riskData.values.map((value, index) => {
      const x = padding + (index * xStep);
      const normalizedValue = value / maxValue;
      const y = height - padding - (normalizedValue * availableHeight);
      return `${x},${y}`;
    });
    
    return `M ${points.join(" L ")}`;
  };

  return (
    <div>
      <div className="card-header">
        <h2 className="card-title">Threat Trend Analysis</h2>
      </div>
      
      {loading ? (
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Analyzing threat trends...</p>
        </div>
      ) : scanCompleted ? (
        <div className="chart-container">
          <div className="chart-header">
            <div className="chart-title">Risk Score Timeline</div>
            <div className="chart-period">7-day View</div>
          </div>
          
          <div className="chart-area">
            <svg width="100%" height="100%" viewBox="0 0 800 240" preserveAspectRatio="xMidYMid meet">
              {/* Y-axis labels */}
              <text x="10" y="30" className="chart-label">100</text>
              <text x="10" y="80" className="chart-label">75</text>
              <text x="10" y="130" className="chart-label">50</text>
              <text x="10" y="180" className="chart-label">25</text>
              <text x="10" y="230" className="chart-label">0</text>
              
              {/* X-axis labels */}
              {riskData.labels.map((label, i) => (
                <text 
                  key={i} 
                  x={30 + (i * (700 / (riskData.labels.length - 1)))} 
                  y="235" 
                  textAnchor="middle" 
                  className="chart-label"
                >
                  {label}
                </text>
              ))}
              
              {/* Horizontal grid lines */}
              <line x1="30" y1="30" x2="730" y2="30" stroke="#e5e7eb" strokeWidth="1" />
              <line x1="30" y1="80" x2="730" y2="80" stroke="#e5e7eb" strokeWidth="1" />
              <line x1="30" y1="130" x2="730" y2="130" stroke="#e5e7eb" strokeWidth="1" />
              <line x1="30" y1="180" x2="730" y2="180" stroke="#e5e7eb" strokeWidth="1" />
              <line x1="30" y1="230" x2="730" y2="230" stroke="#e5e7eb" strokeWidth="1" />
              
              {/* Chart line */}
              <path 
                d={createPath()} 
                fill="none" 
                stroke="#4f46e5" 
                strokeWidth="3" 
                strokeLinecap="round" 
                strokeLinejoin="round"
              />
              
              {/* Data points */}
              {riskData.values.map((value, i) => {
                const x = 30 + (i * (700 / (riskData.labels.length - 1)));
                const y = 230 - ((value / maxValue) * 200);
                return (
                  <circle 
                    key={i} 
                    cx={x} 
                    cy={y} 
                    r="5" 
                    fill="#4f46e5" 
                    stroke="#ffffff" 
                    strokeWidth="2"
                  />
                );
              })}
              
              {/* Area under the line */}
              <path 
                d={`${createPath()} L 730,230 L 30,230 Z`}
                fill="url(#gradient)" 
                fillOpacity="0.2"
              />
              
              {/* Gradient definition */}
              <defs>
                <linearGradient id="gradient" x1="0%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" stopColor="#4f46e5" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="#4f46e5" stopOpacity="0.1" />
                </linearGradient>
              </defs>
            </svg>
          </div>
          
          <div className="chart-footer">
            Higher values indicate increased risk level
          </div>
        </div>
      ) : (
        <div className="empty-state">
          <p>No threat trend data available. Run a scan to analyze security trends.</p>
        </div>
      )}
    </div>
  );
}