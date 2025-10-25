// --- Get Elements ---
const ipTab = document.getElementById('tab-ip');
const hashTab = document.getElementById('tab-hash');
const checkBtn = document.getElementById('check-btn');
const input = document.getElementById('indicator-input');
const loading = document.getElementById('loading');
const resultsContainer = document.getElementById('results-container');

// --- State ---
let currentMode = 'ip'; // 'ip' or 'hash'

// --- Event Listeners ---
ipTab.addEventListener('click', () => {
    currentMode = 'ip';
    ipTab.classList.add('active');
    hashTab.classList.remove('active');
    input.placeholder = 'Enter IP (e.g., 8.8.8.8)';
});

hashTab.addEventListener('click', () => {
    currentMode = 'hash';
    hashTab.classList.add('active');
    ipTab.classList.remove('active');
    input.placeholder = 'Enter SHA256, SHA1, or MD5 hash';
});

checkBtn.addEventListener('click', checkIndicator);

// --- Main Function ---
async function checkIndicator() {
    const indicator = input.value.trim();
    if (!indicator) {
        alert("Please enter an indicator to check.");
        return;
    }

    loading.style.display = 'block';
    resultsContainer.innerHTML = '';

    if (currentMode === 'ip') {
        await checkIpReputation(indicator);
    } else {
        await checkHashReputation(indicator);
    }
}

// --- IP Check Function ---
async function checkIpReputation(ip) {
    try {
        const response = await fetch('/api/check-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Unknown error');
        
        displayIpResults(data.data); 

    } catch (error) {
        resultsContainer.innerHTML = `<p class="feedback incorrect">Error: ${error.message}</p>`;
    } finally {
        loading.style.display = 'none';
    }
}

// --- Hash Check Function ---
async function checkHashReputation(hash) {
    try {
        const response = await fetch('/api/check-hash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hash: hash })
        });
        const data = await response.json();

        if (response.status === 404) {
            resultsContainer.innerHTML = `<p class="feedback correct">This hash was not found in the VirusTotal database.</p>`;
            return;
        }

        if (!response.ok) throw new Error(data.error || 'Unknown error');

        displayHashResults(data.data);

    } catch (error) {
        resultsContainer.innerHTML = `<p class="feedback incorrect">Error: ${error.message}</p>`;
    } finally {
        loading.style.display = 'none';
    }
}

// --- Display Functions ---
function displayIpResults(data) {
    if (!data || Object.keys(data).length === 0) {
        resultsContainer.innerHTML = `<p class="feedback correct">This IP has not been reported to AbuseIPDB.</p>`;
        return;
    }
    let score = data.abuseConfidenceScore;
    let scoreClass = 'correct';
    if (score > 25) scoreClass = 'warn';
    if (score > 75) scoreClass = 'incorrect';

    resultsContainer.innerHTML = `
        <h3>Report for IP: ${data.ipAddress}</h3>
        <div class="report-grid">
            <div class="report-item">
                <strong>Abuse Score:</strong>
                <span class="feedback ${scoreClass}">${score} / 100</span>
            </div>
            <div class="report-item"><strong>Country:</strong><span>${data.countryName || 'N/A'}</span></div>
            <div class="report-item"><strong>Domain:</strong><span>${data.domain || 'N/A'}</span></div>
            <div class="report-item"><strong>ISP:</strong><span>${data.isp || 'N/A'}</span></div>
            <div class="report-item"><strong>Usage Type:</strong><span>${data.usageType || 'N/A'}</span></div>
            <div class="report-item"><strong>Total Reports:</strong><span>${data.totalReports || 0}</span></div>
        </div>
    `;
}

function displayHashResults(data) {
    if (!data || !data.attributes) {
        resultsContainer.innerHTML = `<p class="feedback incorrect">Error: Received an invalid response from VirusTotal.</p>`;
        return;
    }

    const stats = data.attributes.last_analysis_stats;
    const malicious = stats.malicious;
    const suspicious = stats.suspicious;
    const harmless = stats.harmless;
    const undetected = stats.undetected;
    const totalVendors = stats.harmless + stats.suspicious + stats.malicious + stats.undetected;

    // --- THIS IS THE FIX ---
    // The classes are now static. The color is tied to the category, not the number.
    let maliciousClass = 'incorrect'; // Malicious is always red
    let suspiciousClass = 'warn';     // Suspicious is always dark yellow
    let harmlessClass = 'correct';    // Harmless is always green
    // --- END OF FIX ---

    // Overall result color (This logic is still correct)
    let overallResultClass = 'correct';
    if (malicious > 0) {
        overallResultClass = 'incorrect';
    } else if (suspicious > 0) {
        overallResultClass = 'warn';
    }

    // Percentage text color (This logic is also correct)
    let vendorsFlaggedText = "vendors flagged this";
    let vendorsFlaggedTextClass = 'correct'; // Default green (0%)
    if (malicious > 0 || suspicious > 0) {
        const flaggedPercentage = ((malicious + suspicious) / totalVendors) * 100;
        
        if (flaggedPercentage > 60) {
            vendorsFlaggedTextClass = 'incorrect'; // Red
        } else if (flaggedPercentage > 30) {
            vendorsFlaggedTextClass = 'orange-feedback'; // Orange
        } else {
            vendorsFlaggedTextClass = 'warn'; // Dark yellow
        }
    }

    const fileName = data.attributes.meaningful_name || (data.attributes.names && data.attributes.names[0]) || 'N/A';
    
    resultsContainer.innerHTML = `
        <h3>Report for Hash: <span class="hash-text">${data.id}</span></h3>
        <div class="report-grid">
            <div class="report-item">
                <strong>Analysis Result:</strong>
                <span class="feedback ${vendorsFlaggedTextClass}">
                    ${malicious + suspicious} / ${totalVendors} ${vendorsFlaggedText}
                </span>
            </div>
            <div class="report-item">
                <strong>Malicious:</strong>
                <span class="feedback ${maliciousClass}">${malicious}</span>
            </div>
            <div class="report-item">
                <strong>Suspicious:</strong>
                <span class="feedback ${suspiciousClass}">${suspicious}</span>
            </div>
            <div class="report-item">
                <strong>Harmless:</strong>
                <span class="feedback ${harmlessClass}">${harmless}</span>
            </div>
            <div class="report-item">
                <strong>Undetected:</strong>
                <span>${undetected}</span>
            </div>
            <div class="report-item">
                <strong>File Name:</strong>
                <span>${fileName}</span>
            </div>
            <div class="report-item">
                <strong>File Type:</strong>
                <span>${data.attributes.type_description || 'N/A'}</span>
            </div>
            <div class="report-item">
                <strong>First Submission:</strong>
                <span>${new Date(data.attributes.first_submission_date * 1000).toLocaleString() || 'N/A'}</span>
            </div>
            <div class="report-item">
                <strong>Last Analysis:</strong>
                <span>${new Date(data.attributes.last_analysis_date * 1000).toLocaleString() || 'N/A'}</span>
            </div>
            <div class="report-item full-width">
                <strong>SHA256:</strong>
                <span class="hash-text">${data.attributes.sha256 || 'N/A'}</span>
            </div>
            <div class="report-item full-width">
                <strong>MD5:</strong>
                <span class="hash-text">${data.attributes.md5 || 'N/A'}</span>
            </div>
        </div>
    `;
}