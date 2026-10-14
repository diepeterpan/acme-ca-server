/**
 * certificates.js - Handles interactive features on the Certificates screen
 * Compliant with Content-Security-Policy (script-src 'self')
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Revoke Confirmation Modal
    const revokeDialog = document.getElementById('revoke-dialog');
    const revokeForm = document.getElementById('revoke-form');
    const modalDomain = document.getElementById('modal-domain');
    const modalSerial = document.getElementById('modal-serial');
    const cancelBtn = document.getElementById('modal-cancel-btn');

    if (revokeDialog && revokeForm) {
        document.querySelectorAll('.open-revoke-modal').forEach((btn) => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const serial = btn.dataset.serial;
                const domain = btn.dataset.domain || 'this certificate';

                if (modalDomain) modalDomain.textContent = domain;
                if (modalSerial) modalSerial.textContent = serial;
                revokeForm.action = `/certificates/${encodeURIComponent(serial)}/revoke`;

                if (typeof revokeDialog.showModal === 'function') {
                    revokeDialog.showModal();
                } else {
                    revokeDialog.setAttribute('open', '');
                }
            });
        });

        if (cancelBtn) {
            cancelBtn.addEventListener('click', () => {
                if (typeof revokeDialog.close === 'function') {
                    revokeDialog.close();
                } else {
                    revokeDialog.removeAttribute('open');
                }
            });
        }

        // Close when clicking the backdrop
        revokeDialog.addEventListener('click', (event) => {
            const rect = revokeDialog.getBoundingClientRect();
            const isInDialog = (
                rect.top <= event.clientY &&
                event.clientY <= rect.top + rect.height &&
                rect.left <= event.clientX &&
                event.clientX <= rect.left + rect.width
            );
            if (!isInDialog) {
                if (typeof revokeDialog.close === 'function') {
                    revokeDialog.close();
                } else {
                    revokeDialog.removeAttribute('open');
                }
            }
        });
    }

    // 2. Copy Serial to Clipboard
    document.querySelectorAll('.copy-serial').forEach((btn) => {
        btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const serial = btn.dataset.serial;
            if (!serial) return;

            try {
                await navigator.clipboard.writeText(serial);
                const originalHtml = btn.innerHTML;
                btn.innerHTML = '<svg viewBox="0 0 24 24" style="width:14px;height:14px;fill:#059669"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>';
                setTimeout(() => {
                    btn.innerHTML = originalHtml;
                }, 1500);
            } catch (err) {
                console.error('Failed to copy serial: ', err);
            }
        });
    });

    // 3. Flash Alert Dismissal
    const closeAlertBtn = document.getElementById('close-alert');
    const alertBanner = document.getElementById('alert-banner');
    if (closeAlertBtn && alertBanner) {
        closeAlertBtn.addEventListener('click', () => {
            alertBanner.style.display = 'none';
        });
    }

    // 4. Client-side Realtime Domain Search
    const searchInput = document.querySelector('.search-input');
    const tableBody = document.getElementById('cert-table-body');
    if (searchInput && tableBody) {
        searchInput.addEventListener('input', (e) => {
            const query = (e.target.value || '').toLowerCase().trim();
            const rows = tableBody.querySelectorAll('tr[data-domain]');
            rows.forEach((row) => {
                const domain = (row.dataset.domain || '').toLowerCase();
                const serial = (row.dataset.serial || '').toLowerCase();
                if (!query || domain.includes(query) || serial.includes(query)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    }
});
