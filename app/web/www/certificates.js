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
    const certsCountBadge = document.getElementById('certsCountBadge');
    if (searchInput && tableBody) {
        const updateCertFilterCount = () => {
            if (!certsCountBadge) return;
            const rows = tableBody.querySelectorAll('tr[data-domain]');
            const total = parseInt(certsCountBadge.dataset.total, 10) || rows.length;
            let visible = 0;
            rows.forEach((row) => {
                if (row.style.display !== 'none') {
                    visible++;
                }
            });
            if (visible === total) {
                certsCountBadge.textContent = total;
            } else {
                certsCountBadge.textContent = `${visible} / ${total}`;
            }
        };

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
            updateCertFilterCount();
        });

        // Run once on initialization if there is already a filter applied
        if (searchInput.value) {
            updateCertFilterCount();
        }
    }

    // 7. Certificate Details Inspection Modal
    const certDetailsDialog = document.getElementById('cert-details-dialog');
    const modalCertTitle = document.getElementById('modalCertTitle');
    const modalCertSerialSub = document.getElementById('modalCertSerialSub');
    const modalCertLoading = document.getElementById('modalCertLoading');
    const modalCertContent = document.getElementById('modalCertContent');
    const modalCertStatusBadge = document.getElementById('modalCertStatusBadge');
    const modalCertStatusHeading = document.getElementById('modalCertStatusHeading');
    const modalCertValidityWindow = document.getElementById('modalCertValidityWindow');
    const modalCertProgressFill = document.getElementById('modalCertProgressFill');
    const modalCertCapabilities = document.getElementById('modalCertCapabilities');
    const modalCertSanChips = document.getElementById('modalCertSanChips');
    const modalCertHealth = document.getElementById('modalCertHealth');
    const modalCertKey = document.getElementById('modalCertKey');
    const modalCertSignature = document.getElementById('modalCertSignature');
    const modalCertIssuer = document.getElementById('modalCertIssuer');
    const modalCertIssued = document.getElementById('modalCertIssued');
    const modalCertExpires = document.getElementById('modalCertExpires');
    const modalCertAccount = document.getElementById('modalCertAccount');
    const modalCertFingerprint = document.getElementById('modalCertFingerprint');
    const modalCopyFingerprint = document.getElementById('modalCopyFingerprint');
    const modalCertDownloadLink = document.getElementById('modalCertDownloadLink');
    const closeCertDetailsBtn = document.getElementById('cert-details-close-btn');
    const closeCertDetailsBtnBottom = document.getElementById('cert-details-close-btn-bottom');

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    if (certDetailsDialog) {
        setupBackdropClose(certDetailsDialog);
        if (closeCertDetailsBtn) {
            closeCertDetailsBtn.addEventListener('click', () => closeDialog(certDetailsDialog));
        }
        if (closeCertDetailsBtnBottom) {
            closeCertDetailsBtnBottom.addEventListener('click', () => closeDialog(certDetailsDialog));
        }

        const iconSvgs = {
            globe: '<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>',
            lock: '<svg viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>',
            shield: '<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.54-3.08 8.8-7 9.88-3.92-1.08-7-5.34-7-9.88V6.3l7-3.12zM12 6a4 4 0 0 0-4 4c0 1.62.97 3.01 2.37 3.63L9.5 17h5l-.87-3.37A4 4 0 0 0 16 10a4 4 0 0 0-4-4zm0 2a2 2 0 1 1 0 4 2 2 0 0 1 0-4z"/></svg>',
            mail: '<svg viewBox="0 0 24 24"><path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/></svg>',
            feather: '<svg viewBox="0 0 24 24"><path d="M20.24 12.24a6 6 0 0 0-8.49-8.49L5 10.5V19h8.5zM16 8l-2 2"/></svg>',
            alert: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>',
            check: '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>'
        };

        const iconBgColors = {
            globe: { bg: '#eff6ff', color: '#2563eb' },
            lock: { bg: '#faf5ff', color: '#7c3aed' },
            shield: { bg: '#ecfdf5', color: '#059669' },
            mail: { bg: '#fffbeb', color: '#d97706' },
            feather: { bg: '#f5f3ff', color: '#6d28d9' }
        };

        document.querySelectorAll('.open-details-modal').forEach((btn) => {
            btn.addEventListener('click', async (e) => {
                e.preventDefault();
                const serial = btn.dataset.serial;
                if (!serial) return;

                if (modalCertTitle) modalCertTitle.textContent = 'Loading...';
                if (modalCertSerialSub) modalCertSerialSub.textContent = `Serial: ${serial}`;
                if (modalCertLoading) modalCertLoading.style.display = 'block';
                if (modalCertContent) modalCertContent.style.display = 'none';

                openDialog(certDetailsDialog);

                try {
                    const resp = await fetch(`/certificates/${encodeURIComponent(serial)}/details`, {
                        headers: { 'Accept': 'application/json' }
                    });
                    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                    const data = await resp.json();

                    if (modalCertTitle) modalCertTitle.textContent = data.subject_cn || data.primary_domain || 'Certificate';
                    if (modalCertSerialSub) modalCertSerialSub.textContent = `Serial: ${data.serial_number_formatted || data.serial_number}`;

                    if (modalCertStatusBadge) {
                        modalCertStatusBadge.className = `badge badge-${data.status}`;
                        modalCertStatusBadge.textContent = data.status.toUpperCase();
                    }

                    let statusText = 'Active & Secure';
                    let progressColor = '#10b981';
                    if (data.is_revoked) {
                        statusText = `Revoked (${data.revoked_at || 'Revoked'})`;
                        progressColor = '#7c3aed';
                    } else if (data.is_expired) {
                        statusText = 'Expired';
                        progressColor = '#ef4444';
                    } else if (data.is_expiring) {
                        statusText = `Expires in ${data.days_remaining} days`;
                        progressColor = '#f59e0b';
                    } else {
                        statusText = `${data.days_remaining} days remaining`;
                    }

                    if (modalCertStatusHeading) modalCertStatusHeading.textContent = statusText;
                    if (modalCertValidityWindow) modalCertValidityWindow.textContent = `${data.not_valid_before} → ${data.not_valid_after}`;

                    if (modalCertProgressFill) {
                        modalCertProgressFill.style.width = `${Math.min(100, Math.max(0, data.percent_elapsed))}%`;
                        modalCertProgressFill.style.backgroundColor = progressColor;
                    }

                    if (modalCertCapabilities) {
                        modalCertCapabilities.innerHTML = (data.capabilities || []).map((cap) => {
                            const colors = iconBgColors[cap.icon] || { bg: '#eff6ff', color: '#2563eb' };
                            const svg = iconSvgs[cap.icon] || iconSvgs.globe;
                            return `
                                <div class="capability-card">
                                    <div class="capability-icon-wrap" style="background:${colors.bg}; color:${colors.color};">
                                        ${svg}
                                    </div>
                                    <div class="capability-content">
                                        <div class="capability-title">
                                            <span>${escapeHtml(cap.title)}</span>
                                            <span class="badge badge-subtle" style="font-size: 10px; font-weight:700;">${escapeHtml(cap.badge || '')}</span>
                                        </div>
                                        <div class="capability-desc">${escapeHtml(cap.desc)}</div>
                                    </div>
                                </div>
                            `;
                        }).join('');
                    }

                    if (modalCertSanChips) {
                        modalCertSanChips.innerHTML = (data.domains || []).map((dom) => {
                            return `<span class="san-chip">${escapeHtml(dom)}</span>`;
                        }).join('');
                    }

                    if (modalCertHealth) {
                        if (data.healthy) {
                            modalCertHealth.innerHTML = `
                                <div class="health-card health-ok">
                                    <div style="flex-shrink:0;">${iconSvgs.check}</div>
                                    <div>
                                        <div style="font-weight:700; font-size:0.9rem; margin-bottom:0.15rem;">All Security Checks Passed</div>
                                        <div style="font-size:0.82rem; opacity:0.95;">No configuration problems, weak keys, or revocation flags were found. Certificate is active and meets security standards.</div>
                                    </div>
                                </div>
                            `;
                        } else {
                            modalCertHealth.innerHTML = (data.problems || []).map((prob) => {
                                const cardClass = prob.level === 'critical' ? 'health-critical' : 'health-warning';
                                return `
                                    <div class="health-card ${cardClass}">
                                        <div style="flex-shrink:0;">${iconSvgs.alert}</div>
                                        <div>
                                            <div style="font-weight:700; font-size:0.9rem; margin-bottom:0.15rem;">${escapeHtml(prob.title)}</div>
                                            <div style="font-size:0.82rem; opacity:0.95;">${escapeHtml(prob.detail)}</div>
                                        </div>
                                    </div>
                                `;
                            }).join('');
                        }
                    }

                    if (modalCertKey) modalCertKey.textContent = `${data.key_type} ${data.key_size}-bit`;
                    if (modalCertSignature) modalCertSignature.textContent = data.signature_algorithm || 'SHA-256';
                    if (modalCertIssuer) modalCertIssuer.textContent = data.issuer_cn || 'ACME CA Server';
                    if (modalCertIssued) modalCertIssued.textContent = data.not_valid_before || '—';
                    if (modalCertExpires) modalCertExpires.textContent = data.not_valid_after || '—';
                    if (modalCertAccount) modalCertAccount.textContent = data.account_email || (data.account_id ? `Account #${data.account_id}` : 'Standard Account');
                    if (modalCertFingerprint) modalCertFingerprint.textContent = data.fingerprint_sha256 || '—';

                    if (modalCertDownloadLink) {
                        modalCertDownloadLink.href = `/certificates/${encodeURIComponent(data.serial_number)}`;
                    }

                    if (modalCertLoading) modalCertLoading.style.display = 'none';
                    if (modalCertContent) modalCertContent.style.display = 'flex';

                } catch (err) {
                    console.error('Failed to load certificate details:', err);
                    if (modalCertLoading) {
                        modalCertLoading.innerHTML = `
                            <div style="color: #dc2626; padding: 1.5rem;">
                                <div style="font-weight: 700; font-size: 1rem; margin-bottom: 0.5rem;">Failed to load certificate information</div>
                                <div style="font-size: 0.85rem;">Could not retrieve certificate details for serial ${escapeHtml(serial)}.</div>
                            </div>
                        `;
                    }
                }
            });
        });

        if (modalCopyFingerprint && modalCertFingerprint) {
            modalCopyFingerprint.addEventListener('click', async (e) => {
                e.preventDefault();
                const fp = modalCertFingerprint.textContent;
                if (!fp || fp === '—') return;
                try {
                    await navigator.clipboard.writeText(fp);
                    const originalHtml = modalCopyFingerprint.innerHTML;
                    modalCopyFingerprint.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="#059669"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>';
                    setTimeout(() => {
                        modalCopyFingerprint.innerHTML = originalHtml;
                    }, 1500);
                } catch (err) {
                    console.error('Failed to copy fingerprint:', err);
                }
            });
        }
    }
});
