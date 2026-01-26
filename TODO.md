# Continuum - Feature Roadmap

## 🔥 High Priority

### ~~Auto-Update System~~ ✅ DONE
- [x] Version check endpoint (compare local vs GitHub releases)
- [x] Download and apply updates via web UI
- [x] Backup current install before updating
- [x] Rollback capability on failed update
- [x] Update notification banner in UI

### ~~Notification System~~ ✅ DONE
- [x] Email alerts (SMTP configuration)
- [x] Notification preferences per user
- [x] Security event notifications (login alerts)
- [x] Health check notifications (offline/online alerts)
- [x] Job failure notifications
- [x] Weekly report generation (backend scheduler)
- [ ] Webhook support (Slack, Teams, Discord)
- [ ] Custom Reports page with scheduling
  - Weekly report preferences UI
  - Custom report templates
  - Schedule configuration (daily, weekly, monthly)
  - Manual report generation
- [ ] Configurable alert triggers:
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
- [x] CSS theme toggle
- [x] Remember preference
- [x] System preference detection

### Multi-user Roles
- [x ] Admin role (full access)
- [x ] Operator role (manage redirects, view only printers)
- [ x] Viewer role (read-only dashboard)
- [ x] User management page

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
- [x] **Syslog Receiver** - Receive RFC 5424 logs from printers on port 5140
- [x] **HP SNMP Auto-Configuration** - Automatically configure HP printers to send syslog to Continuum

---

## 🔮 Future Enhancements

### Printer Syslog Vendor Expansion
- [ ] Add Canon SNMP OID mappings for syslog server auto-configuration
- [ ] Add Xerox SNMP OID mappings for syslog server auto-configuration
- [ ] Add Epson SNMP OID mappings for syslog server auto-configuration
- [ ] Add Brother SNMP OID mappings for syslog server auto-configuration
- [ ] Research web services API approach for printers without SNMP write support

---

auto snapshots and backups of data allowing rollback at any time incase of a configuraton issue or update etc.