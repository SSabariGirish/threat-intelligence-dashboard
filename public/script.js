// --- Get Elements ---
const ipTab = document.getElementById('tab-ip');
const hashTab = document.getElementById('tab-hash');
const newsTab = document.getElementById('tab-news');
const checkBtn = document.getElementById('check-btn');
const input = document.getElementById('indicator-input');
const lookupForm = document.getElementById('lookup-form');
const loading = document.getElementById('loading');
const resultsContainer = document.getElementById('results-container');

// --- State ---
let currentMode = 'ip'; // 'ip', 'hash', or 'news'

// --- Event Listeners ---
ipTab.addEventListener('click', () => {
    currentMode = 'ip';
    ipTab.classList.add('active');
    hashTab.classList.remove('active');
    newsTab.classList.remove('active');
    input.placeholder = 'Enter IP (e.g., 8.8.8.8)';
    lookupForm.style.display = 'flex';
    resultsContainer.innerHTML = '';
});

hashTab.addEventListener('click', () => {
    currentMode = 'hash';
    hashTab.classList.add('active');
    ipTab.classList.remove('active');
    newsTab.classList.remove('active');
    input.placeholder = 'Enter SHA256, SHA1, or MD5 hash';
    lookupForm.style.display = 'flex';
    resultsContainer.innerHTML = '';
});

newsTab.addEventListener('click', () => {
    currentMode = 'news';
    newsTab.classList.add('active');
    ipTab.classList.remove('active');
    hashTab.classList.remove('active');
    lookupForm.style.display = 'none';
    resultsContainer.innerHTML = '';
    fetchNews(); // Fetch news immediately
});

checkBtn.addEventListener('click', checkIndicator);

// --- Main Function ---
async function checkIndicator() {
    // Only run if not in news mode
    if (currentMode === 'news') return;

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
        if (!response.ok) throw new Error(data.error || 'Unknown IP check error');

        displayIpResults(data.data); // AbuseIPDB data is nested

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

        if (!response.ok) throw new Error(data.error || 'Unknown hash check error');

        displayHashResults(data.data); // VirusTotal data is nested

    } catch (error) {
        resultsContainer.innerHTML = `<p class="feedback incorrect">Error: ${error.message}</p>`;
    } finally {
        loading.style.display = 'none';
    }
}

// --- News Fetch Function ---
async function fetchNews() {
    loading.textContent = 'Fetching latest cyber news...'; // Update loading text
    loading.style.display = 'block';
    resultsContainer.innerHTML = '';

    try {
        const response = await fetch('/api/cyber-news');
        const data = await response.json();

        if (!response.ok) throw new Error(data.error || 'Could not fetch news');

        displayNews(data);

    } catch (error) {
        resultsContainer.innerHTML = `<p class="feedback incorrect">Error: ${error.message}</p>`;
    } finally {
        loading.style.display = 'none';
        loading.textContent = 'Analyzing...'; // Reset loading text
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

    // Static classes for categories
    let maliciousClass = 'incorrect';
    let suspiciousClass = 'warn';
    let harmlessClass = 'correct';

    // Overall result color
    let overallResultClass = 'correct';
    if (malicious > 0) {
        overallResultClass = 'incorrect';
    } else if (suspicious > 0) {
        overallResultClass = 'warn';
    }

    // Percentage text color
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
    
    // Function to safely format dates
    const formatDate = (timestamp) => {
        if (!timestamp) return 'N/A';
        try {
            return new Date(timestamp * 1000).toLocaleString();
        } catch (e) {
            return 'Invalid Date';
        }
    };

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
                <span>${formatDate(data.attributes.first_submission_date)}</span>
            </div>
            <div class="report-item">
                <strong>Last Analysis:</strong>
                <span>${formatDate(data.attributes.last_analysis_date)}</span>
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

function displayNews(articles) {
    if (!articles || articles.length === 0) {
        resultsContainer.innerHTML = `<p class="feedback warn">Could not retrieve any news articles.</p>`;
        return;
    }

    // --- NEW: List of pixel art images ---
    const pixelArtImages = [
        'assets/pixel_art_1.png',
        'assets/pixel_art_2.png',
        'assets/pixel_art_3.png',
        'assets/pixel_art_4.png',
        'assets/pixel_art_5.png',
        'assets/pixel_art_6.png',
        'assets/pixel_art_7.png',
        'assets/pixel_art_8.png',
        'assets/pixel_art_9.png',
        'assets/pixel_art_10.png'
    ];
    // --- END NEW ---

    let newsHtml = '<ul class="news-list">';
    
    articles.forEach(article => {
        let publishedDate = 'No date';
        try {
             if (article.published) {
                 publishedDate = new Date(article.published).toLocaleString();
             }
        } catch (e) { 
             console.error("Could not parse date:", article.published);
        }

        // --- NEW: Randomly select a pixel art image ---
        const randomImage = pixelArtImages[Math.floor(Math.random() * pixelArtImages.length)];
        // --- END NEW ---

        newsHtml += `
            <li class="news-item">
                <a href="${article.link}" target="_blank" rel="noopener noreferrer">
                    <div class="news-content-wrapper"> <div class="news-text">
                            <strong>${article.title || 'No Title'}</strong>
                            <span>${publishedDate}</span>
                        </div>
                        <img src="${randomImage}" alt="Pixel Art" class="news-pixel-art"> </div>
                </a>
            </li>
        `;
    });

    newsHtml += '</ul>';
    resultsContainer.innerHTML = newsHtml;
}

// --- Initial Load ---
// Optionally, load news when the page first loads
// document.addEventListener('DOMContentLoaded', fetchNews);