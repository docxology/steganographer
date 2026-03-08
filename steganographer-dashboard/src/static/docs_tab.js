/**
 * Steganographer Dashboard — Docs Tab
 *
 * Renders documentation markdown files embedded in the server binary.
 * Uses marked.js (loaded from CDN) for client-side markdown→HTML conversion.
 *
 * Architecture:
 * - LEFT:  Sidebar with filterable list of doc files
 * - RIGHT: Rendered markdown content with styled headings, code, tables
 */

// ═══════════════════════════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════════════════════════

let docsFileList = [];
let docsActiveFile = null;
let docsInitialized = false;

// ═══════════════════════════════════════════════════════════════════════════════
// DOM REFERENCES
// ═══════════════════════════════════════════════════════════════════════════════

const docsEl = {
    get sidebar() { return document.getElementById('docs-sidebar'); },
    get fileList() { return document.getElementById('docs-file-list'); },
    get content() { return document.getElementById('docs-content'); },
    get searchInput() { return document.getElementById('docs-search'); },
    get contentTitle() { return document.getElementById('docs-content-title'); },
    get wordCount() { return document.getElementById('docs-word-count'); },
};

// ═══════════════════════════════════════════════════════════════════════════════
// FRIENDLY DOC NAMES
// ═══════════════════════════════════════════════════════════════════════════════

const DOC_METADATA = {
    'README.md': { icon: '📖', label: 'Overview' },
    'AGENTS.md': { icon: '🤖', label: 'Agents' },
    'algorithms.md': { icon: '🧮', label: 'Algorithms' },
    'api-reference.md': { icon: '📡', label: 'API Reference' },
    'architecture.md': { icon: '🏛️', label: 'Architecture' },
    'cli-reference.md': { icon: '⌨️', label: 'CLI Reference' },
    'configuration.md': { icon: '⚙️', label: 'Configuration' },
    'contributing.md': { icon: '🤝', label: 'Contributing' },
    'cryptography.md': { icon: '🔐', label: 'Cryptography' },
    'faq.md': { icon: '❓', label: 'FAQ' },
    'getting-started.md': { icon: '🚀', label: 'Getting Started' },
    'gstreamer.md': { icon: '🎬', label: 'GStreamer' },
    'platforms.md': { icon: '💻', label: 'Platforms' },
    'roadmap.md': { icon: '🗺️', label: 'Roadmap' },
    'security.md': { icon: '🛡️', label: 'Security' },
    'steganography-theory.md': { icon: '📐', label: 'Steganography Theory' },
    'threat-model.md': { icon: '⚠️', label: 'Threat Model' },
};

// ═══════════════════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Initialize the Docs tab. Called once when the Docs tab is first activated.
 */
async function initDocsTab() {
    if (docsInitialized) return;
    docsInitialized = true;

    console.log('[docs] Initializing documentation tab');

    // Setup search filter
    if (docsEl.searchInput) {
        docsEl.searchInput.addEventListener('input', filterDocs);
    }

    // Fetch doc list
    try {
        const res = await fetch('/api/docs');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        docsFileList = await res.json();
        console.log(`[docs] Loaded ${docsFileList.length} documentation files`);
    } catch (err) {
        console.error('[docs] Failed to load docs list:', err);
        docsEl.content.innerHTML = '<p class="docs-error">Failed to load documentation list.</p>';
        return;
    }

    renderSidebar();

    // Auto-load README.md (or first doc) on init
    const defaultDoc = docsFileList.includes('README.md') ? 'README.md' : docsFileList[0];
    if (defaultDoc) {
        loadDoc(defaultDoc);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIDEBAR
// ═══════════════════════════════════════════════════════════════════════════════

function renderSidebar() {
    const list = docsEl.fileList;
    if (!list) return;

    list.innerHTML = '';
    for (const name of docsFileList) {
        const meta = DOC_METADATA[name] || { icon: '📄', label: name.replace('.md', '') };
        const li = document.createElement('li');
        li.className = 'docs-file-item';
        li.dataset.name = name;
        li.innerHTML = `<span class="docs-file-icon">${meta.icon}</span>
            <span class="docs-file-label">${meta.label}</span>
            <span class="docs-file-name">${name}</span>`;
        li.addEventListener('click', () => loadDoc(name));
        list.appendChild(li);
    }
}

function filterDocs() {
    const query = (docsEl.searchInput?.value || '').toLowerCase();
    const items = docsEl.fileList?.querySelectorAll('.docs-file-item') || [];
    for (const item of items) {
        const name = item.dataset.name.toLowerCase();
        const meta = DOC_METADATA[item.dataset.name];
        const label = meta ? meta.label.toLowerCase() : '';
        item.style.display = (name.includes(query) || label.includes(query)) ? '' : 'none';
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOCUMENT LOADING & RENDERING
// ═══════════════════════════════════════════════════════════════════════════════

async function loadDoc(name) {
    if (docsActiveFile === name) return;
    docsActiveFile = name;

    // Update active state in sidebar
    const items = docsEl.fileList?.querySelectorAll('.docs-file-item') || [];
    for (const item of items) {
        item.classList.toggle('active', item.dataset.name === name);
    }

    // Show loading state
    const contentEl = docsEl.content;
    if (!contentEl) return;
    contentEl.innerHTML = '<div class="docs-loading"><span class="docs-spinner"></span> Loading…</div>';

    // Update title
    const meta = DOC_METADATA[name] || { icon: '📄', label: name };
    if (docsEl.contentTitle) {
        docsEl.contentTitle.textContent = `${meta.icon} ${meta.label}`;
    }

    try {
        const res = await fetch(`/api/docs/${encodeURIComponent(name)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const markdown = await res.text();

        // Render markdown to HTML using marked.js
        if (typeof marked !== 'undefined' && marked.parse) {
            contentEl.innerHTML = marked.parse(markdown, {
                gfm: true,
                breaks: false,
            });
        } else {
            // Fallback: render as preformatted text
            contentEl.innerHTML = `<pre class="docs-raw">${escapeHtml(markdown)}</pre>`;
            console.warn('[docs] marked.js not loaded, using raw text fallback');
        }

        // Update word count
        const wordCount = markdown.split(/\s+/).filter(w => w.length > 0).length;
        if (docsEl.wordCount) {
            docsEl.wordCount.textContent = `${wordCount.toLocaleString()} words`;
        }

        // Make links open in new tab
        contentEl.querySelectorAll('a').forEach(a => {
            // Internal doc links: load in-place
            const href = a.getAttribute('href') || '';
            if (href.endsWith('.md') && !href.startsWith('http')) {
                const docName = href.split('/').pop();
                if (docsFileList.includes(docName)) {
                    a.addEventListener('click', (e) => {
                        e.preventDefault();
                        loadDoc(docName);
                    });
                    a.style.cursor = 'pointer';
                    return;
                }
            }
            // External links: open in new tab
            if (href.startsWith('http')) {
                a.setAttribute('target', '_blank');
                a.setAttribute('rel', 'noopener noreferrer');
            }
        });

        console.log(`[docs] Rendered ${name} (${wordCount} words)`);

        // ── Mermaid rendering ───────────────────────────────────────────
        // marked.js renders ```mermaid blocks as <code class="language-mermaid">
        // We need to convert these to <div class="mermaid"> and call mermaid.run()
        if (typeof mermaid !== 'undefined') {
            const mermaidBlocks = contentEl.querySelectorAll('code.language-mermaid');
            if (mermaidBlocks.length > 0) {
                console.log(`[docs] Found ${mermaidBlocks.length} Mermaid diagrams`);
                mermaidBlocks.forEach((block, i) => {
                    const pre = block.parentElement;  // <pre><code class="language-mermaid">
                    const div = document.createElement('div');
                    div.className = 'mermaid';
                    div.textContent = block.textContent;
                    pre.replaceWith(div);
                });
                try {
                    mermaid.run({ nodes: contentEl.querySelectorAll('.mermaid') });
                    console.log(`[docs] Mermaid rendered ${mermaidBlocks.length} diagrams`);
                } catch (err) {
                    console.warn('[docs] Mermaid rendering error:', err);
                }
            }
        }

    } catch (err) {
        console.error(`[docs] Failed to load ${name}:`, err);
        contentEl.innerHTML = `<p class="docs-error">Failed to load "${name}": ${escapeHtml(err.message)}</p>`;
    }
}

function escapeHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// ═══════════════════════════════════════════════════════════════════════════════
// TAB ACTIVATION HOOK
// ═══════════════════════════════════════════════════════════════════════════════

// Listen for tab switches — initialize docs tab on first activation
document.addEventListener('DOMContentLoaded', () => {
    const docsTabBtn = document.getElementById('tab-btn-docs');
    if (docsTabBtn) {
        docsTabBtn.addEventListener('click', () => {
            // Small delay to ensure tab content is visible before fetch
            setTimeout(initDocsTab, 50);
        });
    }
});
