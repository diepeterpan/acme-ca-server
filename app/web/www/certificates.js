/**
 * certificates.js - Handles interactive features on the Certificates screen
 * Compliant with Content-Security-Policy (script-src 'self')
 */

document.addEventListener('DOMContentLoaded', () => {
    // Helper to safely open dialog
    const openDialog = (dialog) => {
        if (!dialog) return;
        if (typeof dialog.showModal === 'function') {
            dialog.showModal();
        } else {
            dialog.setAttribute('open', '');
        }
    };

    // Helper to safely close dialog
    const closeDialog = (dialog) => {
        if (!dialog) return;
        if (typeof dialog.close === 'function') {
            dialog.close();
        } else {
            dialog.removeAttribute('open');
        }
    };

    // Helper to setup backdrop click to close
    const setupBackdropClose = (dialog) => {
        if (!dialog) return;
        dialog.addEventListener('click', (event) => {
            const rect = dialog.getBoundingClientRect();
            const isInDialog = (
                rect.top <= event.clientY &&
                event.clientY <= rect.top + rect.height &&
                rect.left <= event.clientX &&
                event.clientX <= rect.left + rect.width
            );
            if (!isInDialog) {
                closeDialog(dialog);
            }
        });
    };

    // 1. Single Revoke Confirmation Modal
    const revokeDialog = document.getElementById('revoke-dialog');
    const revokeForm = document.getElementById('revoke-form');
    const modalDomain = document.getElementById('modal-domain');
    const modalSerial = document.getElementById('modal-serial');
    const cancelRevokeBtn = document.getElementById('modal-cancel-btn');

    if (revokeDialog && revokeForm) {
        setupBackdropClose(revokeDialog);
        document.querySelectorAll('.open-revoke-modal').forEach((btn) => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const serial = btn.dataset.serial;
                const domain = btn.dataset.domain || 'this certificate';

                if (modalDomain) modalDomain.textContent = domain;
                if (modalSerial) modalSerial.textContent = serial;
                revokeForm.action = `/certificates/${encodeURIComponent(serial)}/revoke`;
                openDialog(revokeDialog);
            });
        });

        if (cancelRevokeBtn) {
            cancelRevokeBtn.addEventListener('click', () => closeDialog(revokeDialog));
        }
    }

    // 2. Single Delete Confirmation Modal
    const deleteDialog = document.getElementById('delete-dialog');
    const deleteForm = document.getElementById('delete-form');
    const deleteModalDomain = document.getElementById('delete-modal-domain');
    const deleteModalSerial = document.getElementById('delete-modal-serial');
    const cancelDeleteBtn = document.getElementById('delete-modal-cancel-btn');

    if (deleteDialog && deleteForm) {
        setupBackdropClose(deleteDialog);
        document.querySelectorAll('.open-delete-modal').forEach((btn) => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const serial = btn.dataset.serial;
                const domain = btn.dataset.domain || 'this certificate';

                if (deleteModalDomain) deleteModalDomain.textContent = domain;
                if (deleteModalSerial) deleteModalSerial.textContent = serial;
                deleteForm.action = `/certificates/${encodeURIComponent(serial)}/delete`;
                openDialog(deleteDialog);
            });
        });

        if (cancelDeleteBtn) {
            cancelDeleteBtn.addEventListener('click', () => closeDialog(deleteDialog));
        }
    }

    // 3. Multi-Select & Batch Action Toolbar
    const selectAllChk = document.getElementById('select-all-certs');
    const batchBar = document.getElementById('batch-action-bar');
    const batchBarTop = document.getElementById('batch-action-bar-top');

    const batchSelectedCount = document.getElementById('batch-selected-count');
    const batchTopSelectedCount = document.getElementById('batch-top-selected-count');
    const batchRevokeCount = document.getElementById('batch-revoke-count');
    const batchTopRevokeCount = document.getElementById('batch-top-revoke-count');
    const batchDeleteCount = document.getElementById('batch-delete-count');
    const batchTopDeleteCount = document.getElementById('batch-top-delete-count');
    const batchTopHint = document.getElementById('batch-top-hint');

    const btnBatchRevoke = document.getElementById('btn-batch-revoke');
    const btnTopBatchRevoke = document.getElementById('btn-top-batch-revoke');
    const btnBatchDelete = document.getElementById('btn-batch-delete');
    const btnTopBatchDelete = document.getElementById('btn-top-batch-delete');
    const btnBatchCancel = document.getElementById('btn-batch-cancel');
    const btnTopBatchCancel = document.getElementById('btn-top-batch-cancel');

    const batchRevokeDialog = document.getElementById('batch-revoke-dialog');
    const batchRevokeForm = document.getElementById('batch-revoke-form');
    const batchRevokeModalCount = document.getElementById('batch-revoke-modal-count');
    const batchRevokeSerialsInput = document.getElementById('batch-revoke-serials-input');
    const batchRevokeCancelBtn = document.getElementById('batch-revoke-cancel-btn');

    const batchDeleteDialog = document.getElementById('batch-delete-dialog');
    const batchDeleteForm = document.getElementById('batch-delete-form');
    const batchDeleteModalCount = document.getElementById('batch-delete-modal-count');
    const batchDeleteSerialsInput = document.getElementById('batch-delete-serials-input');
    const batchDeleteCancelBtn = document.getElementById('batch-delete-cancel-btn');

    if (batchRevokeDialog) setupBackdropClose(batchRevokeDialog);
    if (batchDeleteDialog) setupBackdropClose(batchDeleteDialog);

    if (batchRevokeCancelBtn) {
        batchRevokeCancelBtn.addEventListener('click', () => closeDialog(batchRevokeDialog));
    }
    if (batchDeleteCancelBtn) {
        batchDeleteCancelBtn.addEventListener('click', () => closeDialog(batchDeleteDialog));
    }

    const getSelectedCheckboxes = () => {
        return Array.from(document.querySelectorAll('.cert-select-chk:checked'));
    };

    const updateBatchBar = () => {
        const selected = getSelectedCheckboxes();
        const total = selected.length;

        if (total === 0) {
            if (batchBar) batchBar.style.display = 'none';
            if (batchBarTop) batchBarTop.style.display = 'none';
            if (selectAllChk) selectAllChk.checked = false;
            return;
        }

        if (batchBar) batchBar.style.display = 'flex';
        if (batchBarTop) batchBarTop.style.display = 'block';

        if (batchSelectedCount) batchSelectedCount.textContent = total;
        if (batchTopSelectedCount) batchTopSelectedCount.textContent = total;

        const activeSerials = selected.filter((chk) => chk.dataset.status === 'active').map((chk) => chk.value);
        const revokedSerials = selected.filter((chk) => chk.dataset.status === 'revoked').map((chk) => chk.value);

        if (batchRevokeCount) batchRevokeCount.textContent = activeSerials.length;
        if (batchTopRevokeCount) batchTopRevokeCount.textContent = activeSerials.length;
        if (batchDeleteCount) batchDeleteCount.textContent = revokedSerials.length;
        if (batchTopDeleteCount) batchTopDeleteCount.textContent = revokedSerials.length;

        if (btnBatchRevoke) btnBatchRevoke.disabled = activeSerials.length === 0;
        if (btnTopBatchRevoke) btnTopBatchRevoke.disabled = activeSerials.length === 0;
        if (btnBatchDelete) btnBatchDelete.disabled = revokedSerials.length === 0;
        if (btnTopBatchDelete) btnTopBatchDelete.disabled = revokedSerials.length === 0;

        if (batchTopHint) {
            if (activeSerials.length > 0 && revokedSerials.length === 0) {
                batchTopHint.textContent = 'Active certificates must be revoked before they can be deleted.';
            } else if (revokedSerials.length > 0 && activeSerials.length === 0) {
                batchTopHint.textContent = 'Revoked certificates are ready for permanent deletion.';
            } else {
                batchTopHint.textContent = `${activeSerials.length} active (revocable), ${revokedSerials.length} revoked (deletable).`;
            }
        }

        // Update selectAllChk checked state
        if (selectAllChk) {
            const visibleCheckboxes = Array.from(document.querySelectorAll('#cert-table-body tr')).filter(
                (tr) => tr.style.display !== 'none'
            ).map((tr) => tr.querySelector('.cert-select-chk')).filter(Boolean);

            if (visibleCheckboxes.length > 0) {
                selectAllChk.checked = visibleCheckboxes.every((chk) => chk.checked);
            }
        }
    };

    // Toggle individual checkbox
    document.querySelectorAll('.cert-select-chk').forEach((chk) => {
        chk.addEventListener('change', updateBatchBar);
    });

    // Toggle select all
    if (selectAllChk) {
        selectAllChk.addEventListener('change', () => {
            const isChecked = selectAllChk.checked;
            const visibleRows = Array.from(document.querySelectorAll('#cert-table-body tr')).filter(
                (tr) => tr.style.display !== 'none'
            );
            visibleRows.forEach((tr) => {
                const chk = tr.querySelector('.cert-select-chk');
                if (chk) chk.checked = isChecked;
            });
            updateBatchBar();
        });
    }

    // Cancel batch selection
    const cancelBatch = () => {
        document.querySelectorAll('.cert-select-chk').forEach((chk) => {
            chk.checked = false;
        });
        if (selectAllChk) selectAllChk.checked = false;
        updateBatchBar();
    };

    if (btnBatchCancel) btnBatchCancel.addEventListener('click', cancelBatch);
    if (btnTopBatchCancel) btnTopBatchCancel.addEventListener('click', cancelBatch);

    // Open Batch Revoke Modal
    const handleBatchRevokeClick = (e) => {
        e.preventDefault();
        const selected = getSelectedCheckboxes();
        const activeSerials = selected.filter((chk) => chk.dataset.status === 'active').map((chk) => chk.value);
        if (activeSerials.length === 0) return;

        if (batchRevokeModalCount) batchRevokeModalCount.textContent = activeSerials.length;
        if (batchRevokeSerialsInput) batchRevokeSerialsInput.value = activeSerials.join(',');
        openDialog(batchRevokeDialog);
    };

    if (btnBatchRevoke && batchRevokeDialog) btnBatchRevoke.addEventListener('click', handleBatchRevokeClick);
    if (btnTopBatchRevoke && batchRevokeDialog) btnTopBatchRevoke.addEventListener('click', handleBatchRevokeClick);

    // Open Batch Delete Modal
    const handleBatchDeleteClick = (e) => {
        e.preventDefault();
        const selected = getSelectedCheckboxes();
        const revokedSerials = selected.filter((chk) => chk.dataset.status === 'revoked').map((chk) => chk.value);
        if (revokedSerials.length === 0) return;

        if (batchDeleteModalCount) batchDeleteModalCount.textContent = revokedSerials.length;
        if (batchDeleteSerialsInput) batchDeleteSerialsInput.value = revokedSerials.join(',');
        openDialog(batchDeleteDialog);
    };

    if (btnBatchDelete && batchDeleteDialog) btnBatchDelete.addEventListener('click', handleBatchDeleteClick);
    if (btnTopBatchDelete && batchDeleteDialog) btnTopBatchDelete.addEventListener('click', handleBatchDeleteClick);

    // 4. Copy Serial to Clipboard
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

    // 5. Flash Alert Dismissal
    const closeAlertBtn = document.getElementById('close-alert');
    const alertBanner = document.getElementById('alert-banner');
    if (closeAlertBtn && alertBanner) {
        closeAlertBtn.addEventListener('click', () => {
            alertBanner.style.display = 'none';
        });
    }

    // 6. Client-side Realtime Domain Search
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
            updateBatchBar();
        });
    }
});
