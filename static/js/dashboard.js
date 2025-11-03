let currentScanResults = null;


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


function validateIP(ip) {
  const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipPattern.test(ip);
}

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
  
  fetch('api/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      target_ip: ip,
      mode: mode,
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


document.getElementById('download-btn').addEventListener('click', function() {
  if (!currentScanResults) {
    alert('No scan results to download!');
    return;
  }

  let reportText = `AfriSkana Security Scan Report\n`;
  reportText += `${'='.repeat(50)}\n\n`;
  reportText += `Target IP: ${currentScanResults.targetIp}\n`;
  reportText += `Scan Mode: ${currentScanResults.scanMode}\n`;
  reportText += `Scan Time: ${currentScanResults.scanTime}\n`;
  reportText += `Open Ports Detected: ${currentScanResults.openPorts}\n\n`;
  reportText += `${'='.repeat(50)}\n\n`;

  currentScanResults.vulnerabilities.forEach((vuln, index) => {
    reportText += `${index + 1}. ${vuln.title}\n`;
    reportText += `   Port: ${vuln.port} (${vuln.service})\n`;
    reportText += `   Risk Level: ${vuln.risk.toUpperCase()}\n\n`;
  
    reportText += `   Remediation:\n   ${vuln.remediation}\n\n`;
    reportText += `${'-'.repeat(50)}\n\n`;
  });

  reportText += `\nReport generated by AfriSkana - Privacy-First Security Scanning\n`;
  reportText += `No data is stored on our servers. This report is for your records only.\n`;

  
  const blob = new Blob([reportText], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `afriskana-scan-${currentScanResults.targetIp}-${Date.now()}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
});


document.getElementById('clear-btn').addEventListener('click', function() {
  if (confirm('Are you sure you want to clear the current scan results? This action cannot be undone.')) {
    currentScanResults = null;
    document.getElementById('results-section').classList.remove('show');
    document.getElementById('target-ip').value = '';
    alert('Scan results cleared successfully!');
  }
});

document.getElementById('logout-btn').addEventListener('click', function() {
  if (confirm('Are you sure you want to logout?')) {
    
    currentScanResults = null;
    alert('Logged out successfully! Redirecting to landing page...');

    window.location.href = 'index.html';
  }
});

