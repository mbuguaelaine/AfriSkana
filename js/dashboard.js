// Store current scan results (temporary, cleared on page refresh)
let currentScanResults = null;

// Page navigation
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', function() {
    const pageName = this.getAttribute('data-page');
    
    // Remove active class from all nav items and pages
    document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
    document.querySelectorAll('.page-section').forEach(page => page.classList.remove('active'));
    
    // Add active class to clicked item and corresponding page
    this.classList.add('active');
    document.getElementById(pageName + '-page').classList.add('active');
    
    // Scroll to top
    document.querySelector('.main-content').scrollTop = 0;
  });
});

// Validate IP address
function validateIP(ip) {
  const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipPattern.test(ip);
}

// Scan form submission
document.getElementById('scan-form').addEventListener('submit', function(e) {
  e.preventDefault();
  
  const ipInput = document.getElementById('target-ip');
  const ipError = document.getElementById('ip-error');
  const ip = ipInput.value.trim();
  const mode = document.getElementById('scan-mode').value;
  const button = document.getElementById('scan-button');
  const resultsSection = document.getElementById('results-section');

  // Validate IP
  if (!validateIP(ip)) {
    ipInput.classList.add('error');
    ipError.textContent = 'Please enter a valid IP address (e.g., 192.168.1.1)';
    return;
  }

  // Clear error
  ipInput.classList.remove('error');
  ipError.textContent = '';

  // Hide previous results
  resultsSection.classList.remove('show');

  // Disable button and show loading
  button.disabled = true;
  button.innerHTML = '<span>Scanning Network</span><div class="spinner"></div>';

  // Simulate scan process (Replace with actual API call to your Python backend)
  setTimeout(() => {
    currentScanResults = generateMockResults(ip, mode);
    displayResults(currentScanResults);

    button.disabled = false;
    button.innerHTML = '<span>Launch Scan</span>';
    
    resultsSection.classList.add('show');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 4000);
});

// Generate mock scan results
function generateMockResults(ip, mode) {
  const vulnerabilities = [
    {
      port: 23,
      service: 'Telnet',
      risk: 'critical',
      title: 'Unencrypted Remote Access Protocol Detected',
      description: 'Telnet transmits all data including passwords in plain text, making it vulnerable to eavesdropping and man-in-the-middle attacks.',
      remediation: 'Disable Telnet immediately and replace with SSH (port 22) for secure encrypted remote access. Update firewall rules to block port 23.'
    },
    {
      port: 21,
      service: 'FTP',
      risk: 'high',
      title: 'Insecure File Transfer Protocol Active',
      description: 'FTP lacks encryption and sends credentials in clear text. Common target for credential theft and data interception.',
      remediation: 'Migrate to SFTP (SSH File Transfer Protocol) or FTPS (FTP over SSL/TLS). Ensure all file transfers use encrypted channels.'
    },
    {
      port: 445,
      service: 'SMB',
      risk: 'medium',
      title: 'SMB File Sharing Exposed',
      description: 'Server Message Block protocol detected. If running outdated version (SMBv1), vulnerable to WannaCry-style ransomware attacks.',
      remediation: 'Disable SMBv1, enable SMBv3 with encryption. Restrict SMB access to internal networks only using firewall rules.'
    },
    {
      port: 80,
      service: 'HTTP',
      risk: 'low',
      title: 'Unencrypted Web Traffic',
      description: 'HTTP server detected without SSL/TLS encryption. Data transmitted can be intercepted.',
      remediation: 'Implement HTTPS with valid SSL/TLS certificates. Redirect all HTTP traffic to HTTPS on port 443.'
    }
  ];

  // Privacy mode only shows first 2 vulnerabilities
  const modeVulns = mode === 'privacy' ? vulnerabilities.slice(0, 2) : vulnerabilities;

  return {
    targetIp: ip,
    scanMode: mode === 'standard' ? 'Standard Mode (Full Audit)' : 'Privacy Mode (Essential Ports)',
    scanTime: new Date().toLocaleString(),
    openPorts: modeVulns.length,
    vulnerabilities: modeVulns
  };
}

// Display scan results
function displayResults(results) {
  // Display scan info
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

  // Display vulnerabilities
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

// Download report as text file
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
    reportText += `   Description:\n   ${vuln.description}\n\n`;
    reportText += `   Remediation:\n   ${vuln.remediation}\n\n`;
    reportText += `${'-'.repeat(50)}\n\n`;
  });

  reportText += `\nReport generated by AfriSkana - Privacy-First Security Scanning\n`;
  reportText += `No data is stored on our servers. This report is for your records only.\n`;

  // Create download
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

// Clear results
document.getElementById('clear-btn').addEventListener('click', function() {
  if (confirm('Are you sure you want to clear the current scan results? This action cannot be undone.')) {
    currentScanResults = null;
    document.getElementById('results-section').classList.remove('show');
    document.getElementById('target-ip').value = '';
    alert('Scan results cleared successfully!');
  }
});

// Logout function
document.getElementById('logout-btn').addEventListener('click', function() {
  if (confirm('Are you sure you want to logout?')) {
    // Clear any session data
    currentScanResults = null;
    alert('Logged out successfully! Redirecting to login page...');
    // In a real application, redirect to auth page:
    // window.location.href = 'auth.html';
  }
});