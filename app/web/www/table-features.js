/**
 * table-features.js - Handles client-side sorting and column resizing
 * with localStorage persistence and full keyboard accessibility.
 * Content-Security-Policy compliant (no inline eval).
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

        // Apply saved widths
        headers.forEach((th, idx) => {
            const widthKey = th.dataset.colKey || `col_${idx}`;
            if (savedWidths[widthKey] && savedWidths[widthKey] > 40) {
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
                currentWidth = Math.max(60, startWidth + deltaX);
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
                        }
                    } catch (err) {
                        console.warn('Could not reset saved table width:', err);
                    }
                }
            });
        });
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
     * Public entrypoint to attach features to a table
     */
    window.initTableFeatures = function (table, customKey) {
        if (!table) return;
        const storageKey = customKey || table.dataset.tableId || table.className.split(' ')[0] || 'default';
        initResizableTable(table, storageKey);
        initSortableTable(table);
    };

    /**
     * Auto-initialize all designated tables on DOM load
     */
    document.addEventListener('DOMContentLoaded', () => {
        const tables = document.querySelectorAll('table.cert-table, table.account-table, table.domain-table, table[data-table-id]');
        tables.forEach(table => {
            window.initTableFeatures(table);
        });
    });
})();
