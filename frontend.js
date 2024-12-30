document.addEventListener('DOMContentLoaded', function() {
    const scanButton = document.getElementById('scanButton');
    const resultsContainer = document.getElementById('resultsContainer');
    const exportButton = document.getElementById('exportButton');

    if (!scanButton) {
        console.error('Scan button not found');
        return;
    }

    if (!resultsContainer) {
        console.error('Results container not found');
        return;
    }

    if (!exportButton) {
        console.error('Export button not found');
        return;
    }

    scanButton.addEventListener('click', function() {
        console.log('Start Scan button clicked');
        fetch('http://127.0.0.1:8000/api/scan/start', {
            method: 'POST'
        })
        .then(response => {
            console.log('Response received from /api/scan/start');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Data received:', data);
            const scanId = data.scan_id;
            checkScanStatus(scanId);
        })
        .catch(error => {
            console.error('Error starting scan:', error);
        });
    });

    function checkScanStatus(scanId) {
        console.log('Checking scan status for scan ID:', scanId);
        fetch(`http://127.0.0.1:8000/api/scan/${scanId}/status`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                console.log('Scan status data received:', data);
                if (data.status === 'completed') {
                    fetchScanResults(scanId);
                } else {
                    setTimeout(() => checkScanStatus(scanId), 5000);
                }
            })
            .catch(error => {
                console.error('Error checking scan status:', error);
            });
    }

    function fetchScanResults(scanId) {
        console.log('Fetching scan results for scan ID:', scanId);
        fetch(`http://127.0.0.1:8000/api/scan/${scanId}/results`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                console.log('Scan results data received:', data);
                resultsContainer.innerHTML = '';
                data.findings.forEach(finding => {
                    const findingElement = document.createElement('div');
                    findingElement.classList.add('finding');
                    findingElement.innerHTML = `
                        <h3>Severity: ${finding.severity}</h3>
                        <p>Resource ID: ${finding.resource_id}</p>
                        <p>Rule ID: ${finding.rule_id}</p>
                        <p>Description: ${finding.description}</p>
                        <p>Remediation: ${finding.remediation}</p>
                        <p>Compliance Standards: ${finding.compliance_standards.join(', ')}</p>
                        <p>Timestamp: ${new Date(finding.timestamp).toLocaleString()}</p>
                        <p>Service: ${finding.service}</p>
                        <p>Region: ${finding.region}</p>
                        <p>Account ID: ${finding.account_id}</p>
                    `;
                    resultsContainer.appendChild(findingElement);
                });
            })
            .catch(error => {
                console.error('Error fetching scan results:', error);
            });
    }

    exportButton.addEventListener('click', function() {
        const scanId = resultsContainer.getAttribute('data-scan-id');
        if (!scanId) {
            alert('No scan results to export');
            return;
        }

        const format = document.querySelector('input[name="exportFormat"]:checked').value;
        fetch(`http://127.0.0.1:8000/api/scan/${scanId}/export?format=${format}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.blob();
            })
            .then(blob => {
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = `scan_results.${format}`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
            })
            .catch(error => {
                console.error('Error exporting scan results:', error);
            });
    });
});