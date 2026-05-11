document.addEventListener("DOMContentLoaded", () => {
    if (document.getElementById("news-container")) {
        fetchNews();
        fetchStats();
    }
});

// BUG 5 FIX: Anti-XSS Helper Function
const escapeHTML = str => {
    if (!str) return '';
    return str.replace(/[&<>'"]/g, tag => 
        ({'&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'}[tag] || tag)
    );
};

async function fetchStats() {
    try {
        const res = await fetch('/api/stats');
        const stats = await res.json();
        if(!stats.error) {
            document.getElementById('stat-total').innerText = stats.total;
            document.getElementById('stat-critical').innerText = stats.critical;
            document.getElementById('stat-high').innerText = stats.high; // BUG 6 FIX
            document.getElementById('stat-iocs').innerText = stats.ioc_count;
            document.getElementById('stat-incidents').innerText = stats.open_incidents;
        }
    } catch (e) { console.error("Error fetching stats:", e); }
}

function filterBySeverity(severity) {
    document.getElementById('search-q').value = '';
    document.getElementById('filter-cat').value = '';
    document.getElementById('filter-src').value = '';
    
    // Sync the new dropdown menu with the stat box click
    if(document.getElementById('filter-sev')) {
        document.getElementById('filter-sev').value = severity;
    }
    
    fetchNews(severity);
}

async function fetchNews(severityOverride = '') {
    const container = document.getElementById("news-container");
    container.innerHTML = '<p style="color: var(--accent);">Fetching intelligence feeds...</p>';
    
    const q = document.getElementById('search-q')?.value || '';
    const cat = document.getElementById('filter-cat')?.value || '';
    const src = document.getElementById('filter-src')?.value || '';
    
    // Read the new dropdown. If a stat box was clicked, use the override instead.
    let sev = severityOverride;
    if (!sev) {
        sev = document.getElementById('filter-sev')?.value || '';
    }
    
    try {
        const response = await fetch(`/api/news?q=${q}&category=${cat}&source=${src}&severity=${sev}`);
        const articles = await response.json();
        container.innerHTML = '';

        if (articles.length === 0) {
            container.innerHTML = '<p>No intelligence reports found for these filters.</p>';
            return;
        }

        articles.forEach(article => {
            const card = document.createElement('div');
            card.className = `card sev-${escapeHTML(article.severity)}`;
            
            const safeTitle = escapeHTML(article.title);
            const safeSource = escapeHTML(article.source);
            const safeCat = escapeHTML(article.category);
            const safeAiSummary = escapeHTML(article.ai_summary);
            const safeSummary = escapeHTML(article.summary);
            const safeUrl = escapeHTML(article.url);
            
            let html = `
                <div style="display: flex; justify-content: space-between; align-items: start;">
                    <h3 style="margin-top:0;"><a href="${safeUrl}" target="_blank" style="color: inherit; text-decoration: none; transition: color 0.2s;">${safeTitle}</a></h3>
                    <span class="badge" style="color:var(--bg-dark); background-color:var(--${article.severity.toLowerCase()})">${escapeHTML(article.severity)}</span>
                </div>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem; text-transform: uppercase; letter-spacing: 0.5px;">
                    <strong>SRC:</strong> ${safeSource} &nbsp;|&nbsp; <strong>CAT:</strong> ${safeCat} &nbsp;|&nbsp; <strong>DATE:</strong> ${article.date}
                </p>
            `;
            
            if(article.ai_summary) {
                html += `<p style="line-height: 1.6;"><strong>🤖 AI Analysis:</strong> ${safeAiSummary}</p>`;
            } else {
                html += `<p style="line-height: 1.6;">${safeSummary}</p>`;
            }

            if (article.internal_ip || article.internal_note) {
                const ipDisplay = article.internal_ip.includes('REDACTED') ? `<span class="redacted">${escapeHTML(article.internal_ip)}</span>` : escapeHTML(article.internal_ip);
                const noteDisplay = article.internal_note.includes('REDACTED') ? `<span class="redacted">${escapeHTML(article.internal_note)}</span>` : escapeHTML(article.internal_note);

                html += `<div style="background: rgba(15, 23, 42, 0.5); padding: 1rem; border-radius: 6px; margin-top: 1.5rem; border: 1px dashed var(--border);">
                    <div style="font-size: 0.85rem; color: #cbd5e1;"><strong>Target IP:</strong> ${ipDisplay || 'None'}</div>
                    <div style="font-size: 0.85rem; color: #cbd5e1; margin-top: 0.5rem;"><strong>SOC Note:</strong> ${noteDisplay || 'None'}</div>
                </div>`;
            }

            card.innerHTML = html;
            container.appendChild(card);
        });
    } catch (error) {
        container.innerHTML = `<p style="color: var(--critical)">Failed to load data: ${escapeHTML(error.message)}</p>`;
    }
}