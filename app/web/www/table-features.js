/**
 * table-features.js - Handles client-side sorting, sub-content column resizing,
 * truncation tooltips, column visibility toggling, and layout reset
 * with localStorage persistence and full keyboard accessibility.
 * Content-Security-Policy compliant (no inline eval or unsafe-inline scripts).
 */

(function () {
    'use strict';

    /**
     * Parse cell values for sorting: supports numbers, ISO dates, and strings.
     */
    function parseValue(raw) {
        if (raw === null || raw === undefined) return '';
        const trimmed = String(raw).trim();
        if (trimmed === '' || trimmed === '—' || trimmed === '-') {
            return null;
        }

        // Check if numeric
        if (!isNaN(trimmed) && !isNaN(parseFloat(trimmed)) && isFinite(trimmed)) {
            return parseFloat(trimmed);
        }

        // Check if ISO date or date string (e.g., 2026-10-14 or full ISO)
        if (/^\d{4}-\d{2}-\d{2}(?:T|\s)?/.test(trimmed)) {
            const timestamp = Date.parse(trimmed);
            if (!isNaN(timestamp)) {
                return timestamp;
            }
        }

        return trimmed.toLowerCase();
    }

    /**
     * Compare two parsed values.
     */
    function compareValues(a, b, direction) {
        // Null / empty values always sink to the bottom
        if (a === null && b === null) return 0;
        if (a === null) return 1;
        if (b === null) return -1;

        let result = 0;
        if (typeof a === 'number' && typeof b === 'number') {
            result = a - b;
        } else {
            result = String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
        }

        return direction === 'asc' ? result : -result;
    }

    /**
     * Singleton Hover Tooltip for Truncated Content
     */
    let sharedTooltip = null;
    let tooltipTimeout = null;

    function getOrCreateTooltip() {
        if (!sharedTooltip) {
            sharedTooltip = document.createElement('div');
            sharedTooltip.className = 'table-cell-tooltip';
            sharedTooltip.setAttribute('role', 'tooltip');
            sharedTooltip.setAttribute('aria-hidden', 'true');
            document.body.appendChild(sharedTooltip);

            // Keep tooltip open while hovering over the tooltip itself
            sharedTooltip.addEventListener('mouseenter', () => {
                if (tooltipTimeout) clearTimeout(tooltipTimeout);
            });
            sharedTooltip.addEventListener('mouseleave', () => {
                hideTooltip();
            });
        }
        return sharedTooltip;
    }

    function showTooltip(targetEl, fullText) {
        if (!fullText || fullText.trim().length === 0) return;
        const tooltip = getOrCreateTooltip();
        if (tooltipTimeout) clearTimeout(tooltipTimeout);

        tooltip.innerHTML = '';

        const textSpan = document.createElement('span');
        textSpan.textContent = fullText;
        tooltip.appendChild(textSpan);

        const copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.className = 'tooltip-copy-btn';
        copyBtn.title = 'Copy full value';
        copyBtn.innerHTML = '<svg style="width:11px;height:11px;fill:currentColor;" viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg><span>Copy</span>';

        copyBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(fullText).then(() => {
                    const span = copyBtn.querySelector('span');
                    if (span) span.textContent = 'Copied!';
                    setTimeout(() => {
                        if (span) span.textContent = 'Copy';
                    }, 1500);
                }).catch(() => {});
            }
        });
        tooltip.appendChild(copyBtn);

        const rect = targetEl.getBoundingClientRect();
        tooltip.style.left = '0px';
        tooltip.style.top = '0px';
        tooltip.classList.add('is-visible');

        const tipRect = tooltip.getBoundingClientRect();
        let top = rect.top - tipRect.height - 6;
        if (top < 10) {
            top = rect.bottom + 6;
        }
        let left = rect.left;
        if (left + tipRect.width > window.innerWidth - 10) {
            left = window.innerWidth - tipRect.width - 10;
        }
        if (left < 10) left = 10;

        tooltip.style.top = Math.max(10, top) + 'px';
        tooltip.style.left = left + 'px';
    }

    function hideTooltip() {
        if (!sharedTooltip) return;
        if (tooltipTimeout) clearTimeout(tooltipTimeout);
        tooltipTimeout = setTimeout(() => {
            if (sharedTooltip) {
                sharedTooltip.classList.remove('is-visible');
            }
        }, 150);
    }

    /**
     * Attach hover truncation detector to table body cells
     */
    function attachCellTruncationWatcher(table) {
        if (!table) return;

        table.addEventListener('mouseenter', (e) => {
            const cell = e.target.closest('td');
            if (!cell || !table.classList.contains('table-layout-fixed')) return;

            // Check if cell or immediate child has truncated text
            const inspectEl = cell.firstElementChild || cell;
            const isTruncated = inspectEl.scrollWidth > (inspectEl.clientWidth + 1);

            if (isTruncated) {
                const fullText = cell.getAttribute('data-full-text') || cell.textContent.trim();
                showTooltip(inspectEl, fullText);
            }
        }, true);

        table.addEventListener('mouseleave', (e) => {
            const cell = e.target.closest('td');
            if (cell) {
                hideTooltip();
            }
        }, true);

        window.addEventListener('scroll', () => {
            hideTooltip();
        }, { passive: true });
    }

    /**
     * Initialize Column Resizing on a <table>
     */
    function initResizableTable(table, storageKey) {
        if (!table || table.dataset.resizableInit === 'true') return;
        table.dataset.resizableInit = 'true';

        const thead = table.querySelector('thead');
        if (!thead) return;

        const headerRow = thead.querySelector('tr');
        if (!headerRow) return;

        const headers = Array.from(headerRow.querySelectorAll('th'));
        if (headers.length === 0) return;

        // Load saved widths from localStorage
        let savedWidths = {};
        if (storageKey) {
            try {
                const item = localStorage.getItem('acme_table_widths_' + storageKey);
                if (item) {
                    savedWidths = JSON.parse(item) || {};
                }
            } catch (err) {
                console.warn('Could not read saved table widths:', err);
            }
        }

        const hasSavedWidths = Object.keys(savedWidths).length > 0;
        if (hasSavedWidths) {
            table.classList.add('table-layout-fixed');
        }

        // Apply saved widths
        headers.forEach((th, idx) => {
            const widthKey = th.dataset.colKey || `col_${idx}`;
            if (savedWidths[widthKey] && savedWidths[widthKey] >= 30) {
                th.style.width = savedWidths[widthKey] + 'px';
                th.style.minWidth = savedWidths[widthKey] + 'px';
            }
        });

        // Add resizer handle to each header
        headers.forEach((th, idx) => {
            const resizer = document.createElement('span');
            resizer.className = 'col-resizer';
            resizer.title = 'Drag to resize column (double-click to auto-reset)';
            resizer.setAttribute('aria-hidden', 'true');
            th.appendChild(resizer);

            let startX = 0;
            let startWidth = 0;
            let currentWidth = 0;

            const onPointerMove = (e) => {
                const deltaX = e.pageX - startX;
                // Allow sub-content resizing down to 30px
                currentWidth = Math.max(30, startWidth + deltaX);
                th.style.width = currentWidth + 'px';
                th.style.minWidth = currentWidth + 'px';
            };

            const onPointerUp = () => {
                document.removeEventListener('pointermove', onPointerMove);
                document.removeEventListener('pointerup', onPointerUp);
                document.body.classList.remove('table-col-resizing');
                resizer.classList.remove('active');

                // Save widths to localStorage
                if (storageKey) {
                    try {
                        const widthsToSave = {};
                        headers.forEach((h, hIdx) => {
                            const k = h.dataset.colKey || `col_${hIdx}`;
                            if (h.style.width) {
                                widthsToSave[k] = parseInt(h.style.width, 10);
                            }
                        });
                        localStorage.setItem('acme_table_widths_' + storageKey, JSON.stringify(widthsToSave));
                    } catch (err) {
                        console.warn('Could not save table widths:', err);
                    }
                }
            };

            resizer.addEventListener('pointerdown', (e) => {
                // Prevent sorting trigger on header click
                e.stopPropagation();
                e.preventDefault();

                startX = e.pageX;
                startWidth = th.offsetWidth;
                currentWidth = startWidth;

                // Ensure fixed layout is active during resize to enable shrinking past cell content
                table.classList.add('table-layout-fixed');
                resizer.classList.add('active');
                document.body.classList.add('table-col-resizing');

                document.addEventListener('pointermove', onPointerMove);
                document.addEventListener('pointerup', onPointerUp);
            });

            // Double click resets column width
            resizer.addEventListener('dblclick', (e) => {
                e.stopPropagation();
                e.preventDefault();
                th.style.width = '';
                th.style.minWidth = '';

                if (storageKey) {
                    try {
                        const item = localStorage.getItem('acme_table_widths_' + storageKey);
                        if (item) {
                            const parsed = JSON.parse(item) || {};
                            const k = th.dataset.colKey || `col_${idx}`;
                            delete parsed[k];
                            localStorage.setItem('acme_table_widths_' + storageKey, JSON.stringify(parsed));

                            if (Object.keys(parsed).length === 0) {
                                table.classList.remove('table-layout-fixed');
                            }
                        }
                    } catch (err) {
                        console.warn('Could not reset saved table width:', err);
                    }
                }
            });
        });

        attachCellTruncationWatcher(table);
    }

    /**
     * SVG Icons for sort status (Neutral ↕, Ascending ▲, Descending ▼)
     */
    const SORT_ICONS = {
        none: '<svg class="sort-icon-svg" viewBox="0 0 24 24"><path d="M12 5.83L15.17 9l1.41-1.41L12 3 7.41 7.59 8.83 9 12 5.83zm0 12.34L8.83 15l-1.41 1.41L12 21l4.59-4.59L15.17 15 12 18.17z"/></svg>',
        asc: '<svg class="sort-icon-svg active-sort" viewBox="0 0 24 24"><path d="M12 4l-6.5 8h13L12 4z"/></svg>',
        desc: '<svg class="sort-icon-svg active-sort" viewBox="0 0 24 24"><path d="M12 20l6.5-8h-13L12 20z"/></svg>'
    };

    /**
     * Initialize Column Sorting on a <table>
     */
    function initSortableTable(table) {
        if (!table || table.dataset.sortableInit === 'true') return;
        table.dataset.sortableInit = 'true';

        const thead = table.querySelector('thead');
        const tbody = table.querySelector('tbody');
        if (!thead || !tbody) return;

        const headerRow = thead.querySelector('tr');
        if (!headerRow) return;

        const headers = Array.from(headerRow.querySelectorAll('th'));

        // Cache initial row order for the 3rd state reset
        const initialRows = Array.from(tbody.querySelectorAll('tr'));
        initialRows.forEach((row, i) => {
            row.dataset.originalIndex = String(i);
        });

        headers.forEach((th, colIdx) => {
            // Check if column is non-sortable
            if (th.hasAttribute('data-no-sort') || th.classList.contains('no-sort')) {
                th.classList.add('th-no-sort');
                return;
            }

            th.classList.add('sortable-th');
            th.setAttribute('tabindex', '0');
            th.setAttribute('role', 'columnheader');
            th.setAttribute('aria-sort', 'none');

            // Wrap title text and append icon badge
            const textNodes = [];
            Array.from(th.childNodes).forEach(node => {
                if (!node.classList || !node.classList.contains('col-resizer')) {
                    textNodes.push(node);
                }
            });

            const contentWrapper = document.createElement('div');
            contentWrapper.className = 'th-content-wrapper';

            const titleSpan = document.createElement('span');
            titleSpan.className = 'th-title';
            textNodes.forEach(node => titleSpan.appendChild(node));

            const iconSpan = document.createElement('span');
            iconSpan.className = 'sort-icon-badge';
            iconSpan.innerHTML = SORT_ICONS.none;

            contentWrapper.appendChild(titleSpan);
            contentWrapper.appendChild(iconSpan);

            // Re-insert content before the resizer
            const resizer = th.querySelector('.col-resizer');
            if (resizer) {
                th.insertBefore(contentWrapper, resizer);
            } else {
                th.appendChild(contentWrapper);
            }

            const triggerSort = () => {
                const currentSort = th.getAttribute('aria-sort') || 'none';
                let nextSort = 'asc';
                if (currentSort === 'asc') nextSort = 'desc';
                else if (currentSort === 'desc') nextSort = 'none';

                // Reset all other headers
                headers.forEach(h => {
                    if (h !== th && h.classList.contains('sortable-th')) {
                        h.setAttribute('aria-sort', 'none');
                        const icon = h.querySelector('.sort-icon-badge');
                        if (icon) icon.innerHTML = SORT_ICONS.none;
                    }
                });

                // Update current header
                th.setAttribute('aria-sort', nextSort);
                iconSpan.innerHTML = SORT_ICONS[nextSort];

                // Get current rows in tbody
                const rows = Array.from(tbody.querySelectorAll('tr'));
                // Filter out empty state banner rows if present
                const dataRows = rows.filter(r => !r.querySelector('.empty-state') && r.cells.length > 1);

                if (dataRows.length <= 1) return;

                if (nextSort === 'none') {
                    // Restore original default order
                    dataRows.sort((a, b) => {
                        const idxA = parseInt(a.dataset.originalIndex || '0', 10);
                        const idxB = parseInt(b.dataset.originalIndex || '0', 10);
                        return idxA - idxB;
                    });
                } else {
                    dataRows.sort((rowA, rowB) => {
                        const cellA = rowA.cells[colIdx];
                        const cellB = rowB.cells[colIdx];
                        if (!cellA || !cellB) return 0;

                        const rawA = cellA.hasAttribute('data-sort-val')
                            ? cellA.getAttribute('data-sort-val')
                            : cellA.textContent;
                        const rawB = cellB.hasAttribute('data-sort-val')
                            ? cellB.getAttribute('data-sort-val')
                            : cellB.textContent;

                        const valA = parseValue(rawA);
                        const valB = parseValue(rawB);

                        return compareValues(valA, valB, nextSort);
                    });
                }

                // Re-append in sorted order (preserves existing event listeners & elements)
                dataRows.forEach(row => tbody.appendChild(row));
            };

            // Click listener
            th.addEventListener('click', (e) => {
                if (e.target.closest('.col-resizer')) return;
                triggerSort();
            });

            // Keyboard accessibility (Enter / Space)
            th.addEventListener('keydown', (e) => {
                if (e.target.closest('.col-resizer')) return;
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    triggerSort();
                }
            });
        });
    }

    /**
     * Column Visibility & Reset Toolbar Controls
     */
    function initTableControls(table, storageKey) {
        if (!table || table.dataset.controlsInit === 'true') return;
        table.dataset.controlsInit = 'true';

        const thead = table.querySelector('thead');
        if (!thead) return;
        const headerRow = thead.querySelector('tr');
        if (!headerRow) return;
        const headers = Array.from(headerRow.querySelectorAll('th'));
        if (headers.length <= 1) return;

        // Find or create mount point in search / filter header
        let container = table.closest('.table-container, .table-card, .dist-card, .users-card, .table-responsive, [style*="overflow"]');
        if (!container) container = table.parentElement;

        // Check for designated toolbar container in card, table container, or parent
        let toolbarMount = null;
        if (container) {
            toolbarMount = container.querySelector('.table-toolbar-mount') ||
                           (container.parentNode ? container.parentNode.querySelector('.table-toolbar-mount') : null);
        }
        if (!toolbarMount) {
            // Find existing search-container, filter-container, or card-table-header
            const searchBar = (container && container.parentNode) ? container.parentNode.querySelector('.search-bar, .table-search-box, .filter-tabs, .card-table-header, .users-table-header') : null;
            if (searchBar) {
                toolbarMount = document.createElement('div');
                toolbarMount.className = 'table-toolbar-mount';
                searchBar.appendChild(toolbarMount);
            }
        }

        if (!toolbarMount) return;

        // Read hidden columns from localStorage
        let hiddenCols = [];
        if (storageKey) {
            try {
                const item = localStorage.getItem('acme_table_hidden_' + storageKey);
                if (item) {
                    hiddenCols = JSON.parse(item) || [];
                }
            } catch (err) {
                console.warn('Could not read hidden columns:', err);
            }
        }

        // Apply initial hidden columns
        const applyVisibility = (colIdx, isHidden) => {
            const th = headers[colIdx];
            if (th) {
                if (isHidden) th.classList.add('col-hidden');
                else th.classList.remove('col-hidden');
            }
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(r => {
                const td = r.cells[colIdx];
                if (td) {
                    if (isHidden) td.classList.add('col-hidden');
                    else td.classList.remove('col-hidden');
                }
            });
        };

        headers.forEach((h, idx) => {
            const key = h.dataset.colKey || `col_${idx}`;
            if (hiddenCols.includes(key)) {
                applyVisibility(idx, true);
            }
        });

        // 1. "Columns ⚙️" Dropdown
        const dropdownContainer = document.createElement('div');
        dropdownContainer.className = 'table-cols-dropdown-container';

        const dropdownBtn = document.createElement('button');
        dropdownBtn.type = 'button';
        dropdownBtn.className = 'btn-table-control';
        dropdownBtn.title = 'Customize column visibility';
        dropdownBtn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M3 3h18v2H3V3zm0 16h18v2H3v-2zm0-8h18v2H3v-2z"/></svg><span>Columns</span>';

        const dropdownMenu = document.createElement('div');
        dropdownMenu.className = 'table-cols-dropdown';

        headers.forEach((h, idx) => {
            // Skip action columns or select-all checkbox columns
            const text = (h.querySelector('.th-title') ? h.querySelector('.th-title').textContent : h.textContent).trim();
            if (!text || text.toLowerCase() === 'actions' || text === '') return;

            const key = h.dataset.colKey || `col_${idx}`;
            const isHidden = hiddenCols.includes(key);

            const label = document.createElement('label');
            label.className = 'table-col-toggle-item';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.checked = !isHidden;

            checkbox.addEventListener('change', () => {
                const nowHidden = !checkbox.checked;
                applyVisibility(idx, nowHidden);

                if (nowHidden) {
                    if (!hiddenCols.includes(key)) hiddenCols.push(key);
                } else {
                    hiddenCols = hiddenCols.filter(k => k !== key);
                }

                if (storageKey) {
                    try {
                        localStorage.setItem('acme_table_hidden_' + storageKey, JSON.stringify(hiddenCols));
                    } catch (e) {
                        console.warn('Could not save hidden columns:', e);
                    }
                }
            });

            label.appendChild(checkbox);
            label.appendChild(document.createTextNode(text));
            dropdownMenu.appendChild(label);
        });

        dropdownBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            dropdownMenu.classList.toggle('active');
        });

        document.addEventListener('click', (e) => {
            if (!dropdownContainer.contains(e.target)) {
                dropdownMenu.classList.remove('active');
            }
        });

        dropdownContainer.appendChild(dropdownBtn);
        dropdownContainer.appendChild(dropdownMenu);
        toolbarMount.appendChild(dropdownContainer);

        // 2. "Reset Columns" Button
        const resetBtn = document.createElement('button');
        resetBtn.type = 'button';
        resetBtn.className = 'btn-table-control';
        resetBtn.title = 'Reset all column widths and visibility to default';
        resetBtn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46C19.54 15.03 20 13.57 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 7.74C4.46 8.97 4 10.43 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z"/></svg><span>Reset</span>';

        resetBtn.addEventListener('click', () => {
            // Clear width styles
            headers.forEach((h, idx) => {
                h.style.width = '';
                h.style.minWidth = '';
                applyVisibility(idx, false);
            });
            table.classList.remove('table-layout-fixed');

            // Reset checkboxes
            const checkboxes = dropdownMenu.querySelectorAll('input[type="checkbox"]');
            checkboxes.forEach(cb => { cb.checked = true; });
            hiddenCols = [];

            // Clear localStorage
            if (storageKey) {
                try {
                    localStorage.removeItem('acme_table_widths_' + storageKey);
                    localStorage.removeItem('acme_table_hidden_' + storageKey);
                } catch (e) {
                    console.warn('Could not reset table state in localStorage:', e);
                }
            }
        });

        toolbarMount.appendChild(resetBtn);
    }

    /**
     * Public entrypoint to attach features to a table
     */
    window.initTableFeatures = function (table, customKey) {
        if (!table) return;
        const storageKey = customKey || table.dataset.tableId || table.className.split(' ')[0] || 'default';
        initResizableTable(table, storageKey);
        initSortableTable(table);
        initTableControls(table, storageKey);
    };

    /**
     * Auto-initialize all designated tables on DOM load
     */
    document.addEventListener('DOMContentLoaded', () => {
        const tables = document.querySelectorAll(
            'table.data-table, table.cert-table, table.account-table, table.domain-table, table.users-table, table.fleet-table, table.dist-table, table.ca-table, table[data-table-id]'
        );
        tables.forEach(table => {
            window.initTableFeatures(table);
        });
    });
})();
