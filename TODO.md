# Printer Proxy - Feature Roadmap

## 🔥 High Priority

### ~~Auto-Update System~~ ✅ DONE
- [x] Version check endpoint (compare local vs GitHub releases)
- [x] Download and apply updates via web UI
- [x] Backup current install before updating
- [x] Rollback capability on failed update
- [x] Update notification banner in UI

### Notification System
- [ ] Email alerts (SMTP configuration)
- [ ] Webhook support (Slack, Teams, Discord)
- [ ] Configurable alert triggers:
  - Printer offline
  - Toner low (configurable threshold)
  - Redirect activated/deactivated
  - Failed health checks (consecutive failures)
- [ ] Notification preferences per printer
- [ ] Quiet hours / schedule

---

## ⭐ Medium Priority

### Scheduled Redirects
- [ ] Schedule redirects for maintenance windows
- [ ] Recurring schedules (daily, weekly)
- [ ] Auto-enable/disable based on time
- [ ] Calendar view of scheduled changes

### Backup & Restore
- [ ] Export all settings to JSON/ZIP
- [ ] Export printer configurations
- [ ] Import/restore from backup file
- [ ] Automatic daily backups (configurable)

### API Documentation
- [ ] Swagger/OpenAPI spec
- [ ] Interactive API docs page
- [ ] API key authentication option
- [ ] Rate limiting

---

## 💡 Nice to Have

### Dark Mode
- [ ] CSS theme toggle
- [ ] Remember preference
- [ ] System preference detection

### Multi-user Roles
- [ ] Admin role (full access)
- [ ] Operator role (manage redirects, view only printers)
- [ ] Viewer role (read-only dashboard)
- [ ] User management page

### Printer Groups
- [ ] Create groups (e.g., "Floor 1", "Marketing")
- [ ] Assign printers to groups
- [ ] Filter dashboard by group
- [ ] Bulk actions per group

### Reporting
- [ ] Print volume reports (daily/weekly/monthly)
- [ ] Uptime reports per printer
- [ ] Export to CSV/PDF
- [ ] Scheduled email reports

---

## ✅ Completed Features

- [x] Web-based printer management
- [x] Auto-discovery (mDNS/SNMP)
- [x] NAT-based traffic redirection
- [x] Health monitoring with history
- [x] SNMP statistics (toner, pages, trays)
- [x] Print queue viewing
- [x] Job history tracking
- [x] Audit logging
- [x] User authentication with lockout
- [x] Dashboard with status overview
- [x] Debian package builds
- [x] **Auto-Update System** - Check GitHub releases, one-click update from web UI
