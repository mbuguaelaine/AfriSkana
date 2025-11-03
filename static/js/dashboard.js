let currentScanResults = null;

// Get user email from localStorage (set during login)
const userEmail = localStorage.getItem('userEmail') || 'user@hospital.com';

// Load saved settings
let darkMode = localStorage.getItem('darkMode') === 'true';
let defaultScanMode = localStorage.getItem('defaultScanMode') || 'standard';
let autoClearResults = localStorage.getItem('autoClearResults') !== 'false';

// Apply dark mode on load
if (darkMode) {
  document.body.classList.add('dark-mode');
}

// Update user email display
document.addEventListener('DOMContentLoaded', function() {
  document.querySelector('.user-email').textContent = userEmail;
  document.querySelector('.user-name').textContent = userEmail.split('@')[0];
  document.querySelector('.user-avatar').textContent = userEmail.charAt(0).toUpperCase();
  
  // Set default scan mode
  document.getElementById('scan-mode').value = defaultScanMode;
  
  // Initialize settings page
  initializeSettings();
});

// Navigation
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', function() {
    const pageName = this.getAttribute('data-page');
    
    document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
    document.querySelectorAll('.page-section').forEach(page => page.classList.remove('active'));
    
    this.classList.add('active');
    document.getElementById(pageName + '-page').classList.add('active');
    
    document.querySelector('.main-content').scrollTop = 0;
  });
});

// Initialize Settings Page
function initializeSettings() {
  // Dark Mode Toggle
  const darkModeToggle = document.getElementById('dark-mode-toggle');
  if (darkModeToggle) {
    darkModeToggle.checked = darkMode;
    darkModeToggle.addEventListener('change', function() {
      darkMode = this.checked;
      localStorage.setItem('darkMode', darkMode);
      document.body.classList.toggle('dark-mode', darkMode);
    });
  }
  
  // Default Scan Mode
  const defaultScanModeSelect = document.getElementById('default-scan-mode');
  if (defaultScanModeSelect) {
    defaultScanModeSelect.value = defaultScanMode;
    defaultScanModeSelect.addEventListener('change', function() {
      defaultScanMode = this.value;
      localStorage.setItem('defaultScanMode', defaultScanMode);
      document.getElementById('scan-mode').value = defaultScanMode;
    });
  }
  
  // Auto Clear Results
  const autoClearToggle = document.getElementById('auto-clear-toggle');
  if (autoClearToggle) {
    autoClearToggle.checked = autoClearResults;
    autoClearToggle.addEventListener('change', function() {
      autoClearResults = this.checked;
      localStorage.setItem('autoClearResults', autoClearResults);
    });
  }
  
  // Display current email
  const currentEmailDisplay = document.getElementById('current-email');
  if (currentEmailDisplay) {
    currentEmailDisplay.textContent = userEmail;
  }
  
  // Reset Settings Button
  const resetSettingsBtn = document.getElementById('reset-settings-btn');
  if (resetSettingsBtn) {
    resetSettingsBtn.addEventListener('click', function() {
      if (confirm('Are you sure you want to reset all settings to default?')) {
        localStorage.removeItem('darkMode');
        localStorage.removeItem('defaultScanMode');
        localStorage.removeItem('autoClearResults');
        
        darkMode = false;
        defaultScanMode = 'standard';
        autoClearResults = true;
        
        document.body.classList.remove('dark-mode');
        initializeSettings();
        alert('Settings reset successfully!');
      }
    });
  }
}

// IP Validation
function validateIP(ip) {
  const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipPattern.test(ip);
}

// Scan Form
document.getElementById('scan-form').addEventListener('submit', function(e) {
  e.preventDefault();
  
  const ipInput = document.getElementById('target-ip');
  const ipError = document.getElementById('ip-error');
  const ip = ipInput.value.trim();
  const mode = document.getElementById('scan-mode').value;
  const button = document.getElementById('scan-button');
  const resultsSection = document.getElementById('results-section');

  if (!validateIP(ip)) {
    ipInput.classList.add('error');
    ipError.textContent = 'Please enter a valid IP address (e.g., 192.168.1.1)';
    return;
  }

  ipInput.classList.remove('error');
  ipError.textContent = '';
  resultsSection.classList.remove('show');

  button.disabled = true;
  button.innerHTML = '<span>Scanning Network</span><div class="spinner"></div>';

  console.log(`Sending scan request to backend: IP=${ip}, Mode=${mode}`);
  
  fetch('/api/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      target_ip: ip,
      scan_mode: mode,
    }),
  })
  .then(response => {
    if (!response.ok) {
      return response.json().then(err => {
        throw new Error(err.error || `Server responded with status ${response.status}`);
      });
    }
    return response.json();
  })
  .then(data => {
    console.log("Received data from backend:", data);
    const frontendResults = mapBackendToFrontend(data);
    currentScanResults = frontendResults;
    displayResults(currentScanResults);

    button.disabled = false;
    button.innerHTML = '<span>Launch Scan</span>';
    
    resultsSection.classList.add('show');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  })
  .catch(error => {
    console.error('Scan failed:', error);
    const errorResult = generateErrorResult(ip, mode, error.message);
    currentScanResults = errorResult;
    displayResults(currentScanResults);

    button.disabled = false;
    button.innerHTML = '<span>Launch Scan</span>';
    
    resultsSection.classList.add('show');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
});

function mapBackendToFrontend(backendData) {
  const riskMap = {
    'Critical': 'critical',
    'Warning': 'high', 
    'Informational': 'low' 
  };

  const vulnerabilities = backendData.recommendations.map(vuln => {
    return {
      port: vuln.port,
      service: vuln.service,
      risk: riskMap[vuln.risk_level] || 'low', 
      title: `${vuln.service} Service Detected (Port ${vuln.port})`,
      description: `Version ${vuln.detected_version || 'unknown'} detected. ${vuln.recommendation.startsWith('LIVE') ? 'A specific vulnerability was found.' : ''}`,
      remediation: vuln.recommendation
    };
  });

  return {
    targetIp: backendData.target,
    scanMode: document.getElementById('scan-mode').options[document.getElementById('scan-mode').selectedIndex].text,
    scanTime: new Date(backendData.timestamp * 1000).toLocaleString(),
    openPorts: backendData.ports.length,
    vulnerabilities: vulnerabilities
  };
}

function generateErrorResult(ip, mode, errorMessage) {
  return {
    targetIp: ip,
    scanMode: `${mode} (SCAN FAILED)`,
    scanTime: new Date().toLocaleString(),
    openPorts: 0,
    vulnerabilities: [
      {
        port: 'N/A',
        service: 'Scan Error',
        risk: 'critical',
        title: 'Backend Scan Failed',
        description: `Could not retrieve scan results from the backend. ${errorMessage}`,
        remediation: '1. Ensure the Python server is running (sudo python3 -m flask run --host=0.0.0.0). 2. Check the Python server console for errors (e.g., Nmap permissions, API key). 3. Verify your browser can access http://127.0.0.1:5000.'
      }
    ]
  };
}

function displayResults(results) {
  document.getElementById('scan-info').innerHTML = `
    <div class="scan-info-item">
      <span class="scan-info-label">Target IP</span>
      <span class="scan-info-value">${results.targetIp}</span>
    </div>
    <div class="scan-info-item">
      <span class="scan-info-label">Scan Mode</span>
      <span class="scan-info-value">${results.scanMode}</span>
    </div>
    <div class="scan-info-item">
      <span class="scan-info-label">Scan Time</span>
      <span class="scan-info-value">${results.scanTime}</span>
    </div>
    <div class="scan-info-item">
      <span class="scan-info-label">Open Ports</span>
      <span class="scan-info-value">${results.openPorts}</span>
    </div>
  `;

  const vulnHTML = results.vulnerabilities.map(vuln => `
    <div class="vulnerability-item ${vuln.risk}">
      <div class="vulnerability-header">
        <div>
          <div class="vulnerability-title">${vuln.title}</div>
          <div class="vulnerability-port">Port ${vuln.port} - ${vuln.service}</div>
        </div>
        <span class="risk-badge ${vuln.risk}">${vuln.risk}</span>
      </div>
      <div class="vulnerability-description">${vuln.description}</div>
      <div class="remediation">
        <div class="remediation-title">Recommended Action</div>
        <div class="remediation-steps">${vuln.remediation}</div>
      </div>
    </div>
  `).join('');

  document.getElementById('vulnerability-list').innerHTML = vulnHTML;
}

// Download as PDF using jsPDF
document.getElementById('download-btn').addEventListener('click', function() {
  if (!currentScanResults) {
    alert('No scan results to download!');
    return;
  }

  // Load jsPDF from CDN
  const script = document.createElement('script');
  script.src = 'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js';
  script.onload = function() {
    generatePDF();
  };
  document.head.appendChild(script);
});

function generatePDF() {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  
  let yPos = 20;
  const lineHeight = 7;
  const pageHeight = doc.internal.pageSize.height;
  const margin = 20;
  
  // Helper function to check if we need a new page
  function checkNewPage(additionalSpace = 0) {
    if (yPos + additionalSpace > pageHeight - margin) {
      doc.addPage();
      yPos = 20;
      return true;
    }
    return false;
  }
  
  // Title
  doc.setFontSize(20);
  doc.setFont('helvetica', 'bold');
  doc.text('AfriSkana Security Scan Report', margin, yPos);
  yPos += lineHeight * 2;
  
  // Horizontal line
  doc.setLineWidth(0.5);
  doc.line(margin, yPos, 190, yPos);
  yPos += lineHeight;
  
  // Scan Information
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('Scan Information:', margin, yPos);
  yPos += lineHeight;
  
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.text(`Target IP: ${currentScanResults.targetIp}`, margin, yPos);
  yPos += lineHeight;
  doc.text(`Scan Mode: ${currentScanResults.scanMode}`, margin, yPos);
  yPos += lineHeight;
  doc.text(`Scan Time: ${currentScanResults.scanTime}`, margin, yPos);
  yPos += lineHeight;
  doc.text(`Open Ports Detected: ${currentScanResults.openPorts}`, margin, yPos);
  yPos += lineHeight * 2;
  
  checkNewPage();
  
  // Vulnerabilities
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('Detected Vulnerabilities:', margin, yPos);
  yPos += lineHeight * 1.5;
  
  currentScanResults.vulnerabilities.forEach((vuln, index) => {
    checkNewPage(40);
    
    // Vulnerability number and title
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text(`${index + 1}. ${vuln.title}`, margin, yPos);
    yPos += lineHeight;
    
    // Port and service
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.text(`Port: ${vuln.port} (${vuln.service})`, margin + 5, yPos);
    yPos += lineHeight;
    
    // Risk level with color
    const riskColors = {
      'critical': [239, 68, 68],
      'high': [249, 115, 22],
      'medium': [234, 179, 8],
      'low': [34, 197, 94]
    };
    const color = riskColors[vuln.risk] || [0, 0, 0];
    doc.setTextColor(color[0], color[1], color[2]);
    doc.setFont('helvetica', 'bold');
    doc.text(`Risk Level: ${vuln.risk.toUpperCase()}`, margin + 5, yPos);
    doc.setTextColor(0, 0, 0);
    yPos += lineHeight * 1.5;
    
    // Description
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    const descLines = doc.splitTextToSize(vuln.description, 170);
    descLines.forEach(line => {
      checkNewPage();
      doc.text(line, margin + 5, yPos);
      yPos += lineHeight;
    });
    yPos += lineHeight * 0.5;
    
    // Remediation
    checkNewPage(20);
    doc.setFont('helvetica', 'bold');
    doc.text('Recommended Action:', margin + 5, yPos);
    yPos += lineHeight;
    
    doc.setFont('helvetica', 'normal');
    const remLines = doc.splitTextToSize(vuln.remediation, 170);
    remLines.forEach(line => {
      checkNewPage();
      doc.text(line, margin + 5, yPos);
      yPos += lineHeight;
    });
    
    yPos += lineHeight * 1.5;
    
    // Separator line
    if (index < currentScanResults.vulnerabilities.length - 1) {
      checkNewPage(10);
      doc.setLineWidth(0.2);
      doc.line(margin, yPos, 190, yPos);
      yPos += lineHeight;
    }
  });
  
  // Footer
  checkNewPage(20);
  yPos = pageHeight - 30;
  doc.setFontSize(8);
  doc.setFont('helvetica', 'italic');
  doc.text('Report generated by AfriSkana - Privacy-First Security Scanning', margin, yPos);
  yPos += lineHeight;
  doc.text('No data is stored on our servers. This report is for your records only.', margin, yPos);
  
  // Save the PDF
  doc.save(`afriskana-scan-${currentScanResults.targetIp}-${Date.now()}.pdf`);
}

// Clear Results
document.getElementById('clear-btn').addEventListener('click', function() {
  if (confirm('Are you sure you want to clear the current scan results? This action cannot be undone.')) {
    currentScanResults = null;
    document.getElementById('results-section').classList.remove('show');
    if (autoClearResults) {
      document.getElementById('target-ip').value = '';
    }
    alert('Scan results cleared successfully!');
  }
});

// Logout Button
document.getElementById('settings-logout-btn').addEventListener('click', function() {
    if (confirm('Are you sure you want to logout?')) {
        fetch('/logout', {
            method: 'GET', 
        })
        .then(() => {
            currentScanResults = null;
            localStorage.removeItem('userEmail');

            alert('Logged out successfully! Redirecting to landing page...');
            
            window.location.href = '/'; 
        })
        .catch(error => {
            console.error('Logout failed:', error);
            window.location.href = '/';
        });
    }
});

  