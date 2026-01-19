# Changelog

All notable changes to the Printer Proxy project will be documented in this file.

## [1.2.3] - 2026-01-16

### Added
- **Toast Notifications**: Modern Sonner-style toast notifications replace inline alerts
  - Smooth slide-in/out animations from bottom-right
  - Colored left border and icons for success, error, warning, info
  - Auto-dismiss after 5 seconds with manual close button
  - Dark mode compatible using CSS variables
  - Global `showToast()` function for use in custom scripts

### Changed
- **Full Dark Mode Support**: All UI components now respond to theme toggle
  - Manage Printers page (tables, search, buttons, status pills)
  - Discover Printers page (forms, cards, method/caps badges)
  - Audit Log page (tables, action pills, status indicators)
  - Printer Detail page (alerts, action cards, toner bars)
  - Added missing CSS variables: `--info`, `--primary-bg`, `--muted-bg`

### Fixed
- **Login Redirect Message**: Removed the unnecessary "Please log in to access this page" flash message when visiting the base URL

## [1.2.2] - 2026-01-16

### Added
- **Automated Version Management**: Single source of truth for version numbers
  - Version now defined in `app/version.py` only
  - Build script reads version automatically
  - Templates display version dynamically via Flask context
  - New `scripts/bump-version.sh` for easy version bumping (patch/minor/major)

### Changed
- **Dark Mode Toggle**: Redesigned for a cleaner, more modern look
  - Removed outline border for seamless navbar integration
  - Added subtle hover animation (icon rotation)
  - Larger click target for better usability
  - Smooth press feedback with scale animation

### Fixed
- Fixed slow page transitions caused by synchronous network checks
- Dashboard auto-refresh now uses async updates instead of full page reload

## [1.2.0] - 2024

### Added
- **Dark Mode**: Full dark theme support with toggle in navigation bar
  - Theme preference persisted in localStorage
  - CSS variables for consistent theming across all pages
  - Smooth transitions between light and dark themes

- **Print Queue Monitoring**: SNMP-based print queue collection
  - Real-time queue view with job details (name, owner, pages, status)
  - Support for RFC 2707 Job Monitoring MIB
  - Auto-stores job history when jobs complete

- **Printer Error Logging**: SNMP-based log collection and storage
  - Current logs from printer via SNMP (hrPrinterDetectedErrorState and prtAlertTable)
  - Historical log storage in database
  - Severity indicators (critical, warning, info)

- **Printer Sub-pages**: Organized printer information into dedicated pages
  - Queue: Real-time print queue with SSE live updates
  - Job History: Historical print jobs with statistics
  - Logs: Current printer logs and log history with SSE live updates
  - Clean breadcrumb navigation (Dashboard / Printer / Sub-page)

- **Server-Sent Events (SSE)**: Live updates without page refresh
  - `/api/sse/printer/<id>/queue` - Live queue updates
  - `/api/sse/printer/<id>/logs` - Live log alerts

- **Database Models**:
  - `PrintJobHistory`: Stores completed print jobs with pages, owner, timestamps
  - `PrinterErrorLog`: Stores printer errors with severity and resolution status

### Changed
- Updated printer detail page with quick links to sub-pages
- Modernized all pages with dark mode compatible CSS variables
- Improved form styling and input consistency

### Technical
- Added `app/print_queue.py` module for SNMP queue/log collection
- Added SSE endpoints to routes.py
- Created 3 new templates: printer_queue.html, printer_jobs.html, printer_logs.html

## [1.1.4] - Previous Release

- UI modernization with shadcn-inspired styling
- Login and setup page improvements
- Various bug fixes and improvements

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.2.2 | 2026-01-16 | Automated version management, improved dark mode toggle |
| 1.2.1 | 2026-01-16 | Performance optimization - instant page loads |
| 1.2.0 | 2024 | Dark mode, print queue, job history, error logs, live updates |
| 1.1.4 | 2024 | UI modernization |
| 1.1.0 | 2024 | Initial public release |
