# UI Design System Rules: Sea Blue Minimal

This template defines the visual language and design constraints for the interface, utilizing a **Sea Blue (#006994)** primary color palette paired with a crisp, low-radius geometric layout, managed entirely through centralized CSS variables.

---

## ⚙️ Centralized CSS Variables

Copy and paste these tokens into your global stylesheet to manage the design theme from a single source.

```css
:root {
  /* --- Color Palette (Sea Blue Theme) --- */
  --color-primary: #006994;       /* Core brand Sea Blue */
  --color-primary-hover: #004d6e; /* Deep Ocean for hover states */
  --color-primary-light: #e6f4fa; /* Shallow Aqua for backgrounds/alerts */
  
  /* --- Status Indicators (Sea Blue Harmonized) --- */
  --color-success: #1a7a5d;       /* Deep mint green */
  --color-success-bg: #eaf6f2;    /* Soft mint background */
  --color-warning: #b26a00;       /* Ochre/amber warning */
  --color-warning-bg: #fdf5e6;    /* Soft amber background */
  --color-error: #b92c2c;         /* Crimson red */
  --color-error-bg: #fdf2f2;      /* Soft crimson background */
  
  /* --- Light Mode Neutrals --- */
  --color-bg-main: #f8fafb;       /* Application background */
  --color-bg-surface: #ffffff;    /* Card and container backgrounds */
  --color-text-main: #1c2830;     /* High contrast body text */
  --color-text-muted: #536571;    /* Secondary/subtle text */
  --color-border: #d0dee5;        /* Default subtle layout borders */
  --color-disabled: #f1f5f7;      /* Neutral background for disabled elements */
  --color-disabled-text: #a0aec0; /* Text colour for disabled states */

  /* --- Geometry & Corner Radii (Less Rounded) --- */
  --radius-xs: 2px;               /* Small badges, checkmarks */
  --radius-sm: 4px;               /* Buttons, text inputs, tabs, status tags */
  --radius-md: 6px;               /* Cards, containers, dropdown menus */
  --radius-lg: 8px;               /* Modals, large dialogue overlays */

  /* --- Layout & Spacing Grid --- */
  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 32px;

  /* --- Shadows & Elevation --- */
  --shadow-flat: none;
  --shadow-low: 0 1px 3px rgba(28, 40, 48, 0.05), 0 1px 2px rgba(28, 40, 48, 0.1);
  --shadow-md: 0 4px 6px -1px rgba(28, 40, 48, 0.08), 0 2px 4px -1px rgba(28, 40, 48, 0.04);
  --shadow-high: 0 10px 15px -3px rgba(28, 40, 48, 0.1), 0 4px 6px -2px rgba(28, 40, 48, 0.05);

  /* --- Responsive Breakpoints --- */
  --bp-sm: 640px;                 /* Mobile / Mobile Landscape breakpoint */
  --bp-md: 768px;                 /* Tablet breakpoint */
  --bp-lg: 1024px;                /* Desktop breakpoint */
  --bp-xl: 1280px;                /* Large screen breakpoint */
}
```

---

## 📐 Shape & Geometry Rules

To maintain a modern, sharp, and structured aesthetic, the interface explicitly avoids highly rounded pills in favor of a **semi-sharp geometric grid**.

*   **Buttons & Inputs:** Handled by `--radius-sm` (4px).
*   **Cards & Modules:** Handled by `--radius-md` (6px).
*   **Modals:** Handled by `--radius-lg` (8px).

---

## 🧊 Elevation Hierarchy

Shadows must be used selectively to show depth and interaction stages.

| Elevation Level | Applied To | CSS Variable Reference |
| :--- | :--- | :--- |
| **Level 0 (Flat)** | Page background, layout structural sidebars, tables | `var(--shadow-flat)` |
| **Level 1 (Low)** | Standard cards, input fields, navigation headers | `var(--shadow-low)` |
| **Level 2 (Medium)** | Dropdown menus, popovers, hovering card states | `var(--shadow-md)` |
| **Level 3 (High)** | Modals, dialogue boxes, system notifications | `var(--shadow-high)` |

---

## 🔤 Typography Tokens

Typography scales down slightly for smaller screens to maintain structural balance.

```css
/* --- Type Hierarchy Rules --- */
h1, h2, h3, h4, p {
  margin: 0;
  color: var(--color-text-main);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

.text-h1 { font-size: 32px; line-height: 40px; font-weight: 700; letter-spacing: -0.02em; }
.text-h2 { font-size: 24px; line-height: 32px; font-weight: 600; letter-spacing: -0.01em; }
.text-h3 { font-size: 20px; line-height: 28px; font-weight: 600; }
.text-h4 { font-size: 16px; line-height: 24px; font-weight: 600; }
.text-body { font-size: 14px; line-height: 22px; font-weight: 400; color: var(--color-text-main); }
.text-muted { font-size: 14px; line-height: 22px; font-weight: 400; color: var(--color-text-muted); }
.text-small { font-size: 12px; line-height: 16px; font-weight: 500; }

@media (max-width: 640px) {
  .text-h1 { font-size: 26px; line-height: 34px; }
  .text-h2 { font-size: 20px; line-height: 28px; }
  .text-h3 { font-size: 18px; line-height: 24px; }
}
```

---

## 🏗️ Structural Layout Architecture

### 1. Global App Layout Shell
```css
.app-shell {
  display: grid;
  grid-template-columns: 260px 1fr;
  grid-template-rows: 64px 1fr;
  grid-template-areas:
    "sidebar navbar"
    "sidebar main";
  height: 100vh;
  background-color: var(--color-bg-main);
}
```

### 2. Top Navigation Bar
```css
.navbar {
  grid-area: navbar;
  background-color: var(--color-bg-surface);
  border-bottom: 1px solid var(--color-border);
  box-shadow: var(--shadow-low);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 var(--space-lg);
}
```

### 3. Sidebar Navigation
```css
.sidebar {
  grid-area: sidebar;
  background-color: var(--color-bg-surface);
  border-right: 1px solid var(--color-border);
  padding: var(--space-lg) var(--space-md);
  display: flex;
  flex-direction: column;
  gap: var(--space-sm);
}

.sidebar-item {
  display: flex;
  align-items: center;
  padding: var(--space-sm) var(--space-md);
  color: var(--color-text-muted);
  border-radius: var(--radius-sm);
  text-decoration: none;
}

.sidebar-item.active {
  background-color: var(--color-primary-light);
  color: var(--color-primary);
  font-weight: 500;
}
```

---

## 📋 Form Layouts & System Controls

Forms use clear spacing, explicit labels, and multi-column grid layouts that collapse predictably.

### 1. Multi-Column Form Grid
```css
.form-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: var(--space-md) var(--space-lg);
}

.form-group-full {
  grid-column: span 2;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: var(--space-xs);
}

.form-label {
  font-size: 14px;
  font-weight: 500;
  color: var(--color-text-main);
}
```

### 2. Form Fields & Active State
```css
.input-field {
  background-color: var(--color-bg-surface);
  color: var(--color-text-main);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  padding: var(--space-sm) var(--space-md);
  font-size: 14px;
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.input-field:focus {
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--color-primary-light);
  outline: none;
}
```

---

## 🔘 Interactive Element States

Ensures consistent visual user feedback across all clickable elements.

```css
/* --- Disabled Triggers --- */
.btn-primary:disabled,
.input-field:disabled {
  background-color: var(--color-disabled);
  color: var(--color-disabled-text);
  border-color: var(--color-border);
  cursor: not-allowed;
  pointer-events: none;
  box-shadow: none;
}

/* --- Inline Loading Spinners --- */
.btn-loading {
  position: relative;
  color: transparent !important;
}

.btn-loading::after {
  content: "";
  position: absolute;
  width: 16px;
  height: 16px;
  top: 50%;
  left: 50%;
  margin-top: -8px;
  margin-left: -8px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-radius: 50%;
  border-top-color: #ffffff;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* --- Content Skeleton States --- */
.skeleton {
  background-color: var(--color-disabled);
  background-image: linear-gradient(
    90deg,
    var(--color-disabled) 0px,
    var(--color-border) 50px,
    var(--color-disabled) 100px
  );
  background-size: 200% 100%;
  animation: shimmer 1.5s infinite linear;
  border-radius: var(--radius-xs);
}

@keyframes shimmer {
  0% { background-position: -100% 0; }
  100% { background-position: 100% 0; }
}
```

---

## 🔳 Modals and Overlay Containers

Maintains sharp, clean layout depths using maximum context shadows and semi-sharp corner radii.

```css
/* --- Background Dim Overlay --- */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
  background-color: rgba(28, 40, 48, 0.4); /* Subdued matching brand neutral */
  backdrop-filter: blur(2px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

/* --- Centered Modal Chassis --- */
.modal-container {
  background-color: var(--color-bg-surface);
  border-radius: var(--radius-lg); /* Sharp, low-radius 8px */
  box-shadow: var(--shadow-high);
  width: 100%;
  max-width: 540px;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  border: 1px solid var(--color-border);
}

.modal-header {
  padding: var(--space-lg);
  border-bottom: 1px solid var(--color-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.modal-body {
  padding: var(--space-lg);
  max-height: calc(100vh - 200px);
  overflow-y: auto;
}

.modal-footer {
  padding: var(--space-md) var(--space-lg);
  background-color: var(--color-bg-main);
  border-top: 1px solid var(--color-border);
  display: flex;
  justify-content: flex-end;
  gap: var(--space-sm);
