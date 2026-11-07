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
let docsLoadedFile = null;
let docsInitialized = false;
let docsInitPromise = null;
let docsSearchBound = false;
let docsLoadPromise = null;
let docsLoadController = null;
let docsLoadGeneration = 0;
let docsTargetFragment = '';

// API names are identities relative to the repository's docs/ directory.
const DOCS_BASE_URL = new URL('/docs/', window.location.href);

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
    'ots-integration.md': { icon: '⏳', label: 'OpenTimestamps' },
    'key-rotation.md': { icon: '🔑', label: 'Key Rotation' },
};

// ═══════════════════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Called by the dashboard's shared switchTab action, including on revisits.
 * Only a successful list is retained; overlapping activations share one promise.
 */
function initDocsTab() {
    if (!docsSearchBound && docsEl.searchInput) {
        docsEl.searchInput.addEventListener('input', filterDocs);
        docsSearchBound = true;
    }
    if (docsInitPromise) return docsInitPromise;
    if (docsInitialized) {
        if (docsActiveFile && docsLoadedFile !== docsActiveFile) {
            return loadDoc(docsActiveFile, docsTargetFragment);
        }
        return Promise.resolve();
    }

    showDocsMessage('Loading documentation list…', 'docs-loading');
    docsInitPromise = (async () => {
        try {
            const res = await fetch('/api/docs');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            docsFileList = await res.json();
            renderSidebar();
            docsInitialized = true;

            const defaultDoc = docsFileList.includes('README.md') ? 'README.md' : docsFileList[0];
            if (defaultDoc) {
                // Keep list initialization independent of a slow document or diagram.
                loadDoc(defaultDoc);
            } else {
                showDocsMessage('No documentation is available in this dashboard.', 'docs-placeholder');
            }
        } catch (err) {
            docsInitialized = false;
            console.error('[docs] Failed to load docs list:', err);
            showDocsMessage('Failed to load documentation list. Select Docs again or use Retry.', 'docs-error');
            const item = document.createElement('li');
            const retry = document.createElement('button');
            retry.type = 'button';
            retry.className = 'docs-file-item';
            retry.textContent = 'Retry documentation list';
            retry.addEventListener('click', initDocsTab);
            item.appendChild(retry);
            docsEl.fileList?.replaceChildren(item);
        }
    })().finally(() => {
        docsInitPromise = null;
    });
    return docsInitPromise;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIDEBAR
// ═══════════════════════════════════════════════════════════════════════════════

function renderSidebar() {
    const list = docsEl.fileList;
    if (!list) return;

    list.replaceChildren();
    for (const name of docsFileList) {
        const meta = DOC_METADATA[name] || { icon: '📄', label: name.replace(/\.md$/i, '') };
        const li = document.createElement('li');
        li.className = 'docs-file-entry';
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'docs-file-item';
        button.dataset.name = name;
        button.title = name;
        for (const [className, text] of [
            ['docs-file-icon', meta.icon],
            ['docs-file-label', meta.label],
            ['docs-file-name', name],
        ]) {
            const span = document.createElement('span');
            span.className = className;
            span.textContent = text;
            if (className === 'docs-file-icon') span.setAttribute('aria-hidden', 'true');
            button.appendChild(span);
        }
        button.addEventListener('click', () => loadDoc(name));
        li.appendChild(button);
        list.appendChild(li);
    }
    filterDocs();
}

function filterDocs() {
    const query = (docsEl.searchInput?.value || '').trim().toLowerCase();
    const items = docsEl.fileList?.querySelectorAll('.docs-file-item[data-name]') || [];
    for (const item of items) {
        const name = item.dataset.name.toLowerCase();
        const label = (DOC_METADATA[item.dataset.name]?.label || '').toLowerCase();
        // Hide the list wrapper so CSS display:flex on the button cannot
        // override hidden, and nonmatches leave keyboard navigation too.
        item.parentElement.hidden = !name.includes(query) && !label.includes(query);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOCUMENT LOADING & RENDERING
// ═══════════════════════════════════════════════════════════════════════════════

function showDocsMessage(message, className) {
    const paragraph = document.createElement('p');
    paragraph.className = className;
    paragraph.textContent = message;
    docsEl.content?.replaceChildren(paragraph);
    if (docsEl.wordCount) docsEl.wordCount.textContent = '—';
}

function loadDoc(name, fragment = '') {
    const contentEl = docsEl.content;
    // Never turn a markdown path into an arbitrary server/filesystem request.
    if (!contentEl || !docsFileList.includes(name)) return Promise.resolve(false);
    if (docsActiveFile === name) {
        docsTargetFragment = fragment;
        if (docsLoadedFile === name) {
            scrollDocToFragment(fragment);
            return Promise.resolve(true);
        }
        if (docsLoadPromise) return docsLoadPromise;
    }

    docsLoadController?.abort();
    const controller = new AbortController();
    const generation = ++docsLoadGeneration;
    const isCurrent = () => generation === docsLoadGeneration
        && docsActiveFile === name && !controller.signal.aborted;
    docsLoadController = controller;
    docsActiveFile = name;
    docsLoadedFile = null;
    docsTargetFragment = fragment;

    const items = docsEl.fileList?.querySelectorAll('.docs-file-item[data-name]') || [];
    for (const item of items) {
        const active = item.dataset.name === name;
        item.classList.toggle('active', active);
        if (active) item.setAttribute('aria-current', 'page');
        else item.removeAttribute('aria-current');
    }

    showDocsMessage('Loading…', 'docs-loading');
    contentEl.setAttribute('aria-busy', 'true');
    const meta = DOC_METADATA[name] || { icon: '📄', label: name };
    if (docsEl.contentTitle) docsEl.contentTitle.textContent = `${meta.icon} ${meta.label}`;

    docsLoadPromise = (async () => {
        try {
            const res = await fetch(`/api/docs/${encodeURIComponent(name)}`, { signal: controller.signal });
            if (!isCurrent()) return false;
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const markdown = await res.text();
            if (!isCurrent()) return false;
            const draft = await renderDocMarkdown(markdown, generation, isCurrent);
            if (!isCurrent() || !draft) return false;

            prepareDocLinks(draft, name);
            contentEl.replaceChildren(...draft.childNodes);
            docsLoadedFile = name;
            const wordCount = markdown.split(/\s+/).filter(word => word.length > 0).length;
            if (docsEl.wordCount) docsEl.wordCount.textContent = `${wordCount.toLocaleString()} words`;
            scrollDocToFragment(docsTargetFragment);
            return true;
        } catch (err) {
            if (!isCurrent() || err.name === 'AbortError') return false;
            console.error(`[docs] Failed to load ${name}:`, err);
            showDocsMessage(`Failed to load "${name}": ${err.message}. Select this document again to retry.`, 'docs-error');
            return false;
        }
    })().finally(() => {
        if (isCurrent()) {
            docsLoadPromise = null;
            docsLoadController = null;
            contentEl.removeAttribute('aria-busy');
        }
    });
    return docsLoadPromise;
}

async function renderDocMarkdown(markdown, generation, isCurrent) {
    const draft = document.createElement('div');
    let sanitized = false;
    try {
        if (typeof marked !== 'undefined' && typeof marked.parse === 'function'
            && typeof DOMPurify !== 'undefined' && typeof DOMPurify.sanitize === 'function') {
            const rawHtml = await marked.parse(markdown, { gfm: true, breaks: false });
            if (!isCurrent()) return null;
            // This is the only HTML sink. Never insert marked output when
            // the sanitizer is absent or throws, including in offline mode.
            draft.innerHTML = DOMPurify.sanitize(rawHtml, {
                USE_PROFILES: { html: true, svg: true, svgFilters: true },
            });
            sanitized = true;
        }
    } catch (err) {
        console.warn('[docs] Markdown rendering unavailable; showing text:', err);
    }
    if (!isCurrent()) return null;
    if (!sanitized) {
        const pre = document.createElement('pre');
        pre.className = 'docs-raw';
        pre.textContent = markdown;
        draft.replaceChildren(pre);
        return draft;
    }

    const blocks = draft.querySelectorAll('code.language-mermaid');
    if (!blocks.length || typeof mermaid === 'undefined' || typeof mermaid.run !== 'function') {
        return draft;
    }

    const diagrams = [];
    for (const [index, block] of blocks.entries()) {
        const node = document.createElement('div');
        node.className = 'mermaid';
        node.id = `docs-mermaid-${generation}-${index}`;
        node.textContent = block.textContent;
        diagrams.push({ node, source: block.textContent });
        const pre = block.parentElement;
        if (pre?.tagName === 'PRE') pre.replaceWith(node);
        else block.replaceWith(node);
    }

    // Mermaid needs connected elements for layout. Render in an inert,
    // offscreen document, never in the active article. The page's strict
    // Mermaid security configuration is deliberately left intact.
    draft.className = 'docs-content';
    draft.setAttribute('aria-hidden', 'true');
    draft.setAttribute('inert', '');
    Object.assign(draft.style, {
        position: 'fixed',
        left: '-100000px',
        top: '0',
        width: `${docsEl.content?.clientWidth || 800}px`,
        pointerEvents: 'none',
    });
    document.body.appendChild(draft);
    try {
        await mermaid.run({ nodes: diagrams.map(diagram => diagram.node) });
    } catch (err) {
        if (isCurrent()) console.warn('[docs] Mermaid rendering error:', err);
        for (const { node, source } of diagrams) {
            const pre = document.createElement('pre');
            const code = document.createElement('code');
            code.className = 'language-mermaid';
            code.textContent = source;
            pre.appendChild(code);
            node.replaceWith(pre);
        }
        const notice = document.createElement('p');
        notice.className = 'docs-error';
        notice.textContent = 'Diagrams could not be rendered; their source is shown below.';
        draft.prepend(notice);
    } finally {
        draft.remove();
    }
    return isCurrent() ? draft : null;
}

function prepareDocLinks(draft, sourceName) {
    const sourceUrl = new URL(sourceName, DOCS_BASE_URL);
    const identities = new Map(docsFileList.map(name => [new URL(name, DOCS_BASE_URL).pathname, name]));
    for (const link of draft.querySelectorAll('a[href]')) {
        const href = link.getAttribute('href').trim();
        let url;
        try {
            url = new URL(href, sourceUrl);
        } catch {
            markUnavailableDocLink(link, href);
            continue;
        }
        if (((url.protocol === 'https:' || url.protocol === 'http:') && url.origin !== sourceUrl.origin)
            || url.protocol === 'mailto:') {
            link.setAttribute('href', url.href);
            link.setAttribute('target', '_blank');
            link.setAttribute('rel', 'noopener noreferrer');
            continue;
        }

        const targetName = url.origin === sourceUrl.origin
            && (url.protocol === 'https:' || url.protocol === 'http:')
            ? identities.get(url.pathname) : null;
        if (!targetName) {
            markUnavailableDocLink(link, href);
            continue;
        }
        // Preserve the whole identity: plans/.../README.md is not README.md.
        // Even opening this link's href separately stays on the dashboard.
        link.setAttribute('href', url.hash || '#');
        link.removeAttribute('target');
        link.removeAttribute('download');
        link.addEventListener('click', event => {
            event.preventDefault();
            loadDoc(targetName, url.hash);
        });
    }
}

function markUnavailableDocLink(link, href) {
    const label = document.createElement('span');
    label.className = 'docs-unavailable-link';
    label.textContent = `${link.textContent || href} (unavailable in dashboard)`;
    label.title = `Not embedded in this dashboard: ${href}`;
    link.replaceWith(label);
}

function scrollDocToFragment(fragment) {
    const content = docsEl.content;
    if (!content) return;
    if (!fragment || fragment === '#') {
        content.scrollTop = 0;
        return;
    }
    let id;
    try {
        id = decodeURIComponent(fragment.slice(1));
    } catch {
        return;
    }
    const target = Array.from(content.querySelectorAll('[id], a[name]'))
        .find(node => node.id === id || node.getAttribute('name') === id);
    target?.scrollIntoView({ block: 'start' });
}
