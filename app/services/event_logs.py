"""
Event Logs - SNMP-based printer event log collection

Queries HP printers via SNMP to collect event logs.
Uses pysnmp v7 async API.
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class PrinterEvent:
    """Represents a printer event/log entry."""
    code: int
    severity: str = "info"  # info, warning, error, critical
    message: str = ""
    description: str = ""
    time_display: str = ""  # Human-readable time (e.g., "2h 15m ago")
    occurred_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "description": self.description,
            "time_display": self.time_display,
            "occurred_at": self.occurred_at.isoformat()
        }


# Printer alert severity from Printer MIB
ALERT_SEVERITY = {
    1: "other",
    2: "critical",
    3: "error",
    4: "warning",
    5: "info",
}

# Alert codes from Printer MIB (common ones)
STANDARD_ALERT_CODES = {
    1: "Cover Open",
    2: "Cover Closed",
    3: "Interlock Open",
    4: "Interlock Closed",
    5: "Input Tray Missing",
    6: "Input Tray Media Empty",
    7: "Input Tray Media Low",
    8: "Output Tray Missing",
    9: "Output Tray Near Full",
    10: "Output Tray Full",
    11: "Marker Supply Missing",
    12: "Marker Supply Empty",
    13: "Marker Supply Almost Empty",
    14: "Marker Waste Almost Full",
    15: "Marker Waste Full",
    501: "Door Open",
    502: "Jam",
    503: "Toner Low",
    504: "Toner Empty",
    505: "Paper Low",
    506: "Paper Empty",
    507: "Offline",
    508: "Needs Attention",
}

# HP Event Code database
# Note: HP printers only provide numeric event codes via SNMP - no text descriptions.
# The descriptions must be translated client-side using HP's documentation.
# This is the same approach used by HP Web Jetadmin and HP Smart.

# Event codes are structured as follows:
# - 8xxx-9xxx: Basic print/scan events
# - 10xxx-19xxx: Power/wake/job events
# - 90xxx-99xxx: MFP events (scan, copy, fax)
# - 300xxx-399xxx: Status codes (newer HP firmware)

HP_EVENT_CODES = {
    # === Basic Print Events (8xxx-9xxx) ===
    8396: ("info", "Print Started", "Print job started processing"),
    8700: ("info", "Print Completed", "Print job completed successfully"),
    8701: ("info", "Print Cancelled", "Print job was cancelled"),
    8702: ("warning", "Print Failed", "Print job failed to complete"),
    9892: ("info", "Sleep Mode", "Printer entered sleep mode"),
    9893: ("info", "Deep Sleep", "Printer entered deep sleep mode"),
    
    # === Power/Wake Events (10xxx-13xxx) ===
    10001: ("info", "Power On", "Printer powered on"),
    10002: ("info", "Power Off", "Printer powered off"),
    10003: ("info", "Restart", "Printer restarted"),
    10004: ("info", "Cold Start", "Cold start completed"),
    10005: ("info", "Warm Start", "Warm start completed"),
    13121: ("info", "Wake Up", "Printer woke from sleep mode"),
    13122: ("info", "Wake Network", "Woke from network activity"),
    13123: ("info", "Wake Button", "Woke from button press"),
    13124: ("info", "Wake Job", "Woke from incoming job"),
    
    # === Paper Events (11xxx) ===
    11001: ("error", "Paper Jam", "Paper jam detected"),
    11002: ("info", "Jam Cleared", "Paper jam has been cleared"),
    11003: ("warning", "Paper Low", "Paper supply is running low"),
    11004: ("error", "Paper Out", "Paper tray is empty"),
    11005: ("info", "Paper Added", "Paper was added to tray"),
    11006: ("info", "Tray Changed", "Paper tray was changed"),
    11007: ("warning", "Wrong Paper", "Paper size mismatch"),
    11008: ("warning", "Manual Feed", "Waiting for manual paper feed"),
    
    # === Toner/Ink Events (12xxx) ===
    12001: ("warning", "Toner Low", "Toner level is running low"),
    12002: ("error", "Toner Empty", "Toner cartridge is empty - replace"),
    12003: ("info", "Toner Replaced", "New toner cartridge installed"),
    12004: ("warning", "Toner Mismatch", "Incorrect toner installed"),
    12010: ("warning", "Ink Low", "Ink level is running low"),
    12011: ("error", "Ink Empty", "Ink cartridge is empty - replace"),
    12012: ("info", "Ink Replaced", "New ink cartridge installed"),
    12020: ("warning", "Drum Low", "Imaging drum nearing end of life"),
    12021: ("error", "Drum Empty", "Imaging drum needs replacement"),
    12022: ("info", "Drum Replaced", "New imaging drum installed"),
    12030: ("warning", "Waste Toner Full", "Waste toner container is full"),
    12031: ("info", "Waste Replaced", "Waste toner container replaced"),
    
    # === Cover/Door Events (13xxx) ===
    13001: ("warning", "Door Open", "A door or cover is open"),
    13002: ("info", "Door Closed", "Door or cover has been closed"),
    13003: ("warning", "Front Cover Open", "Front cover is open"),
    13004: ("warning", "Rear Cover Open", "Rear cover is open"),
    13005: ("warning", "Side Cover Open", "Side cover is open"),
    13006: ("warning", "Top Cover Open", "Top cover is open"),
    13007: ("warning", "ADF Cover Open", "ADF cover is open"),
    
    # === Service Events (14xxx-15xxx) ===
    14001: ("warning", "Service Required", "Scheduled maintenance needed"),
    14002: ("info", "Service Done", "Service completed successfully"),
    14003: ("warning", "Fuser Warning", "Fuser approaching end of life"),
    14004: ("warning", "Transfer Warning", "Transfer kit approaching end of life"),
    14005: ("warning", "Roller Warning", "Rollers approaching end of life"),
    15001: ("error", "Fuser Error", "Fuser unit error"),
    15002: ("error", "Scanner Error", "Scanner error detected"),
    15003: ("error", "Motor Error", "Motor failure detected"),
    15004: ("error", "Sensor Error", "Sensor failure detected"),
    15005: ("error", "Communication Error", "Internal communication error"),
    
    # === Network Events (16xxx) ===
    16001: ("info", "Network Connected", "Network connection established"),
    16002: ("warning", "Network Disconnected", "Network connection lost"),
    16003: ("info", "DHCP Success", "Obtained IP address via DHCP"),
    16004: ("warning", "DHCP Failed", "Failed to obtain IP address"),
    16005: ("info", "WiFi Connected", "Connected to WiFi network"),
    16006: ("warning", "WiFi Disconnected", "WiFi connection lost"),
    
    # === Job Events (18xxx-19xxx) ===
    18479: ("info", "Job Received", "Print job received from client"),
    18480: ("info", "Job Queued", "Job added to print queue"),
    18481: ("info", "Job Started", "Job started processing"),
    18876: ("info", "Job Completed", "Job finished successfully"),
    18877: ("info", "Job Cancelled", "Job was cancelled by user"),
    18878: ("warning", "Job Failed", "Job failed to complete"),
    19244: ("info", "Ready", "Printer is ready"),
    19245: ("info", "Idle", "Printer is idle"),
    19246: ("info", "Busy", "Printer is busy"),
    19261: ("info", "Sleep Mode", "Printer is in sleep mode"),
    
    # === MFP Scan Events (91xxx-92xxx) ===
    91001: ("info", "Scan Started", "Scan job started"),
    91002: ("info", "Scan Complete", "Scan job completed"),
    91003: ("warning", "Scan Failed", "Scan job failed"),
    91004: ("info", "Scan Cancelled", "Scan job cancelled"),
    91379: ("info", "Scan Complete", "Document scan completed"),
    91380: ("info", "Scan to Email", "Scanned to email address"),
    91381: ("info", "Scan to Network", "Scanned to network folder"),
    91382: ("info", "Scan to USB", "Scanned to USB drive"),
    
    # === MFP Copy Events (92xxx-93xxx) ===
    92001: ("info", "Copy Started", "Copy job started"),
    92002: ("info", "Copy Complete", "Copy job completed"),
    92003: ("warning", "Copy Failed", "Copy job failed"),
    92473: ("info", "Copy Complete", "Copy operation completed"),
    92474: ("info", "Copy Cancelled", "Copy operation cancelled"),
    
    # === MFP Fax Events (92600-93000) ===
    92649: ("info", "Fax Sent", "Fax transmitted successfully"),
    92650: ("info", "Fax Received", "Incoming fax received"),
    92651: ("warning", "Fax Failed", "Fax transmission failed"),
    92652: ("info", "Fax Cancelled", "Fax operation cancelled"),
    92653: ("warning", "Fax Busy", "Fax destination was busy"),
    92654: ("warning", "Fax No Answer", "Fax destination did not answer"),
    
    # === MFP Email/Folder Events (93xxx-94xxx) ===
    93684: ("info", "Email Sent", "Email sent successfully"),
    93685: ("warning", "Email Failed", "Email delivery failed"),
    93686: ("info", "Email Queued", "Email added to queue"),
    93814: ("info", "Scan to Folder", "File saved to network folder"),
    93815: ("warning", "Folder Error", "Network folder access failed"),
    93954: ("info", "Scan Started", "Scan operation started"),
    93955: ("info", "Scan Processing", "Processing scanned document"),
    94092: ("info", "Copy Started", "Copy operation started"),
    94093: ("info", "Copy Processing", "Processing copy job"),
    94989: ("info", "Job Queued", "Job added to queue"),
    94990: ("info", "Job Processing", "Job is being processed"),
    
    # === MFP Completion Events (95xxx) ===
    95001: ("info", "Print Complete", "Print job completed"),
    95002: ("info", "Fax Received", "Fax received and printed"),
    95003: ("warning", "Fax Failed", "Fax operation failed"),
    95004: ("info", "Copy Complete", "Copy operation finished"),
    95005: ("info", "Scan Complete", "Scan operation finished"),
    95006: ("info", "Email Complete", "Email operation finished"),
    95007: ("info", "File Saved", "File saved successfully"),
    95008: ("info", "Job Done", "Job finished successfully"),
    95009: ("info", "Ready", "Device ready for next job"),
    95010: ("info", "Idle", "Device is idle"),
    
    # === HP Status Codes - 300000 Range (Newer Firmware) ===
    # These are used by newer HP LaserJet Pro, Enterprise, and PageWide models
    
    # Ready/Idle states (302100-302150)
    # Note: These codes can appear in jam event sequences as status updates
    302108: ("info", "Ready", "Printer ready or jam cleared"),
    302109: ("info", "Processing", "Processing print job"),
    302110: ("info", "Warming Up", "Warming up print engine"),
    302111: ("warning", "Attention Required", "User attention required"),
    302112: ("info", "Idle", "Printer is idle"),
    302113: ("info", "Busy", "Printer is busy processing"),
    302114: ("info", "Calibrating", "Performing calibration"),
    302115: ("info", "Cleaning", "Running cleaning cycle"),
    302116: ("info", "Initializing", "Printer is initializing"),
    302117: ("info", "Self-Test", "Running self-test"),
    302118: ("info", "Firmware Update", "Updating firmware"),
    302119: ("info", "Restarting", "Printer is restarting"),
    302120: ("info", "Sleep Mode", "Printer in sleep mode"),
    302121: ("info", "Energy Save", "Energy saving mode active"),
    302122: ("info", "Deep Sleep", "Deep sleep mode active"),
    302123: ("info", "Auto-Off", "Auto-off mode active"),
    
    # Job events (302200-302299)
    # Note: 302232, 302240, 302277 appear in jam sequences per HP logs
    302200: ("info", "Job Start", "Job processing started"),
    302201: ("info", "Job End", "Job processing ended"),
    302202: ("info", "Page Printed", "Page printed successfully"),
    302203: ("info", "Pages Complete", "All pages printed"),
    302204: ("info", "Job Received", "Job received from client"),
    302205: ("info", "Job Queued", "Job added to queue"),
    302206: ("info", "Job Cancelled", "Job was cancelled"),
    302207: ("warning", "Job Error", "Job completed with errors"),
    302208: ("info", "Job Held", "Job held in queue"),
    302209: ("info", "Job Released", "Job released from hold"),
    302210: ("info", "Job Deleted", "Job deleted from queue"),
    302211: ("info", "Collating", "Collating pages"),
    302212: ("info", "Stapling", "Stapling document"),
    302213: ("info", "Hole Punching", "Hole punching document"),
    302214: ("info", "Folding", "Folding document"),
    302215: ("info", "Binding", "Binding document"),
    302216: ("info", "Duplexing", "Printing duplex"),
    302217: ("info", "N-Up", "Printing multiple pages per sheet"),
    302218: ("info", "Watermark", "Adding watermark"),
    # Jam-related job events (from HP printer logs)
    302232: ("error", "Paper Jam", "Paper jam - job interrupted"),
    302240: ("error", "Paper Jam", "Paper jam - feeding error"),
    302277: ("error", "Paper Jam", "Paper jam - media stopped"),
    
    # Supply events (302300-302399)
    302300: ("warning", "Low Supply", "A supply is running low"),
    302301: ("warning", "Very Low Supply", "A supply is very low"),
    302302: ("error", "Supply Empty", "A supply is depleted"),
    302303: ("info", "Supply Replaced", "Supply was replaced"),
    302304: ("warning", "Supply Mismatch", "Incorrect supply installed"),
    302305: ("warning", "Supply Missing", "A supply is missing"),
    302306: ("warning", "Black Low", "Black toner/ink low"),
    302307: ("warning", "Cyan Low", "Cyan toner/ink low"),
    302308: ("warning", "Magenta Low", "Magenta toner/ink low"),
    302309: ("warning", "Yellow Low", "Yellow toner/ink low"),
    302310: ("error", "Black Empty", "Black toner/ink empty"),
    302311: ("error", "Cyan Empty", "Cyan toner/ink empty"),
    302312: ("error", "Magenta Empty", "Magenta toner/ink empty"),
    302313: ("error", "Yellow Empty", "Yellow toner/ink empty"),
    302320: ("warning", "Drum Low", "Imaging drum low"),
    302321: ("error", "Drum Empty", "Imaging drum depleted"),
    302330: ("warning", "Waste Full Soon", "Waste container nearly full"),
    302331: ("error", "Waste Full", "Waste container full"),
    
    # Paper/Media events (302400-302499)
    302400: ("warning", "Paper Low", "Paper supply is running low"),
    302401: ("error", "Paper Out", "Paper tray is empty"),
    302402: ("info", "Paper Added", "Paper was added"),
    302403: ("warning", "Paper Mismatch", "Paper size/type mismatch"),
    302404: ("warning", "Manual Feed Required", "Waiting for manual feed"),
    302405: ("info", "Tray Selected", "Input tray selected"),
    302406: ("warning", "Tray Missing", "Input tray is missing"),
    302407: ("info", "Tray Inserted", "Input tray was inserted"),
    302408: ("warning", "Output Full", "Output tray is full"),
    302409: ("info", "Output Cleared", "Output tray was cleared"),
    302410: ("info", "Size Detected", "Paper size auto-detected"),
    302411: ("info", "Type Selected", "Paper type selected"),
    # Jam-related paper events (from HP printer logs)
    302489: ("error", "Paper Jam", "Paper jam - input area"),
    
    # Jam events (302500-302549)
    302500: ("error", "Paper Jam", "Paper jam detected"),
    302501: ("info", "Jam Cleared", "Paper jam was cleared"),
    302502: ("error", "Jam Input", "Jam in input area"),
    302503: ("error", "Jam Output", "Jam in output area"),
    302504: ("error", "Jam Fuser", "Jam in fuser area"),
    302505: ("error", "Jam Duplex", "Jam in duplex unit"),
    302506: ("error", "Jam ADF", "Jam in document feeder"),
    302507: ("warning", "Jam Possible", "Possible paper jam"),
    302508: ("info", "Clear Area", "Clear jam from indicated area"),
    
    # Door/Cover events (302600-302649)
    302600: ("warning", "Door Open", "A door or cover is open"),
    302601: ("info", "Door Closed", "Door or cover was closed"),
    302602: ("warning", "Front Door Open", "Front door is open"),
    302603: ("warning", "Rear Door Open", "Rear door is open"),
    302604: ("warning", "Top Cover Open", "Top cover is open"),
    302605: ("warning", "ADF Cover Open", "ADF cover is open"),
    302606: ("warning", "Cartridge Door Open", "Cartridge access door open"),
    # Jam-related cover events (from HP printer logs)
    302625: ("error", "Paper Jam", "Paper jam - open cover to clear"),
    
    # Network/Connectivity (302700-302799)
    302700: ("info", "Network Connected", "Network connected"),
    302701: ("warning", "Network Disconnected", "Network disconnected"),
    302702: ("info", "WiFi Connected", "WiFi connected"),
    302703: ("warning", "WiFi Disconnected", "WiFi disconnected"),
    302704: ("info", "IP Assigned", "IP address assigned"),
    302705: ("warning", "IP Conflict", "IP address conflict"),
    302706: ("info", "USB Connected", "USB device connected"),
    302707: ("info", "USB Disconnected", "USB device disconnected"),
    
    # Scan/Copy/Fax (302800-302899)
    302800: ("info", "Scan Started", "Scan job started"),
    302801: ("info", "Scan Complete", "Scan job completed"),
    302802: ("warning", "Scan Error", "Scan job error"),
    302803: ("info", "Scan Cancelled", "Scan job cancelled"),
    302810: ("info", "Copy Started", "Copy job started"),
    302811: ("info", "Copy Complete", "Copy job completed"),
    302812: ("warning", "Copy Error", "Copy job error"),
    302813: ("info", "Copy Cancelled", "Copy job cancelled"),
    302820: ("info", "Fax Sending", "Fax is sending"),
    302821: ("info", "Fax Sent", "Fax sent successfully"),
    302822: ("warning", "Fax Failed", "Fax failed"),
    302823: ("info", "Fax Received", "Fax received"),
    302824: ("info", "Fax Cancelled", "Fax cancelled"),
    
    # Service/Maintenance (302900-302999)
    302900: ("warning", "Service Required", "Scheduled service required"),
    302901: ("info", "Service Complete", "Service completed"),
    302902: ("warning", "Fuser Warning", "Fuser needs attention"),
    302903: ("warning", "Roller Warning", "Rollers need attention"),
    302904: ("warning", "Transfer Warning", "Transfer kit needs attention"),
    302905: ("info", "Maintenance Mode", "In maintenance mode"),
    302906: ("error", "Hardware Error", "Hardware error detected"),
    302907: ("critical", "System Error", "System error - restart required"),
    
    # Authentication/Security (303000-303099)
    303000: ("info", "Login Success", "User login successful"),
    303001: ("warning", "Login Failed", "User login failed"),
    303002: ("info", "Logout", "User logged out"),
    303003: ("warning", "Session Timeout", "Session timed out"),
    303004: ("info", "PIN Accepted", "PIN code accepted"),
    303005: ("warning", "PIN Rejected", "PIN code rejected"),
    303006: ("info", "Card Accepted", "Access card accepted"),
    303007: ("warning", "Card Rejected", "Access card rejected"),
    
    # Firmware/Updates (303100-303199)
    303100: ("info", "Update Available", "Firmware update available"),
    303101: ("info", "Update Started", "Firmware update started"),
    303102: ("info", "Update Complete", "Firmware update complete"),
    303103: ("warning", "Update Failed", "Firmware update failed"),
    303104: ("info", "Rebooting", "Rebooting after update"),
    
    # Additional Status Events (303200-303500)
    # Note: 303146, 303228, 303524 appear in jam sequences per HP logs
    303146: ("error", "Paper Jam", "Paper jam - status update"),
    303147: ("info", "Configuration", "Configuration changed"),
    303148: ("info", "Settings Saved", "Settings saved"),
    303228: ("error", "Paper Jam", "Paper jam - event logged"),
    303229: ("info", "Alert Cleared", "Alert condition cleared"),
    303524: ("error", "Paper Jam", "Paper jam detected"),
}


def categorize_hp_event_code(code: int) -> tuple:
    """Categorize unknown HP event codes by their numeric range.
    
    HP event codes follow patterns based on their numeric value:
    - Different code ranges indicate different event categories
    - This provides reasonable fallback when we don't have an exact mapping
    
    Returns: (severity, message, description)
    """
    # HP Event Code Ranges (based on HP documentation patterns):
    #
    # 8xxx-9xxx: Basic print/sleep events
    # 10xxx-19xxx: Power, wake, job lifecycle events
    # 90xxx-99xxx: MFP events (scan, copy, fax)
    #
    # 300xxx-309xxx: Status/state codes (newer firmware)
    #   302xxx: Core printer status
    #   303xxx: Extended status/logging
    #   304xxx: Configuration events
    #   305xxx: Job processing events
    #   306xxx: Media handling events
    #   307xxx: Network/connectivity events
    #   308xxx: MFP (scan/copy/fax) events
    #   309xxx: Service/maintenance events
    #
    # 310xxx-319xxx: Job/document events
    # 320xxx-329xxx: Media/paper events
    # 330xxx-339xxx: Supplies events
    # 340xxx-349xxx: Hardware/component events
    # 350xxx+: Extended/model-specific events
    
    if 8000 <= code < 10000:
        return ('info', 'Print Event', f'Print/sleep event (code {code})')
    
    elif 10000 <= code < 20000:
        return ('info', 'System Event', f'Power/system event (code {code})')
    
    elif 90000 <= code < 100000:
        return ('info', 'MFP Event', f'Scan/copy/fax event (code {code})')
    
    # 302xxx - Core status (we have many of these mapped)
    elif 302000 <= code < 303000:
        sub = (code - 302000) // 100
        categories = {
            0: ('info', 'Initializing', 'Printer initialization'),
            1: ('info', 'Ready', 'Printer ready state'),
            2: ('info', 'Job Processing', 'Processing print job'),
            3: ('warning', 'Supply Alert', 'Supply level change'),
            4: ('warning', 'Media Alert', 'Paper/media issue'),
            5: ('error', 'Paper Jam', 'Paper jam detected'),
            6: ('warning', 'Cover/Door', 'Cover or door event'),
            7: ('info', 'Network', 'Network event'),
            8: ('info', 'MFP', 'Scan/copy/fax event'),
            9: ('warning', 'Service', 'Service required'),
        }
        if sub in categories:
            sev, msg, desc = categories[sub]
            return (sev, msg, f'{desc} (code {code})')
        return ('info', 'Status', f'Status event (code {code})')
    
    # 303xxx - Extended status
    elif 303000 <= code < 304000:
        return ('info', 'Status Log', f'Status logged (code {code})')
    
    # 304xxx - Configuration
    elif 304000 <= code < 305000:
        return ('info', 'Config Change', f'Configuration change (code {code})')
    
    # 305xxx - Job processing
    elif 305000 <= code < 306000:
        return ('info', 'Job Event', f'Job processing event (code {code})')
    
    # 306xxx - Media handling
    elif 306000 <= code < 307000:
        return ('info', 'Media Event', f'Media handling event (code {code})')
    
    # 307xxx - Network
    elif 307000 <= code < 308000:
        return ('info', 'Network', f'Network event (code {code})')
    
    # 308xxx - MFP events
    elif 308000 <= code < 309000:
        return ('info', 'MFP Event', f'MFP event (code {code})')
    
    # 309xxx - Service
    elif 309000 <= code < 310000:
        return ('warning', 'Service', f'Service event (code {code})')
    
    # 310xxx-319xxx - Job/document events
    elif 310000 <= code < 320000:
        return ('info', 'Document', f'Document event (code {code})')
    
    # 320xxx-329xxx - Media/paper events  
    elif 320000 <= code < 330000:
        return ('info', 'Paper', f'Paper/media event (code {code})')
    
    # 330xxx-339xxx - Supplies events
    elif 330000 <= code < 340000:
        return ('warning', 'Supplies', f'Supplies event (code {code})')
    
    # 340xxx-349xxx - Hardware/component events
    elif 340000 <= code < 350000:
        return ('info', 'Hardware', f'Hardware event (code {code})')
    
    # 350xxx+ - Extended events
    elif code >= 350000:
        return ('info', 'Extended', f'Extended event (code {code})')
    
    # Default fallback
    else:
        return ('info', f'Code {code}', f'HP event code {code}')


def get_logs(ip: str, community: str = 'public') -> List[PrinterEvent]:
    """Get logs/events for a printer by IP.
    
    Queries multiple SNMP OIDs to collect printer alerts/logs:
    1. prtAlertTable - Standard Printer MIB alert table
    2. hrPrinterDetectedErrorState - Host Resources MIB error bits
    3. HP Event Log - HP-specific event log table
    
    Uses pysnmp v7 async API with asyncio.
    
    Note: HP printers only provide numeric event codes via SNMP - no text
    descriptions are available. We translate codes using HP_EVENT_CODES,
    with smart fallback categorization for unknown codes.
    """
    import asyncio
    
    async def collect_logs():
        logs = []
        
        try:
            from pysnmp.hlapi.v3arch.asyncio import (
                get_cmd, next_cmd, CommunityData, UdpTransportTarget,
                ObjectType, ObjectIdentity, ContextData, SnmpEngine
            )
            
            engine = SnmpEngine()
            target = await UdpTransportTarget.create((ip, 161), timeout=3, retries=2)
            
            # 1. Walk prtAlertTable for standard alerts
            try:
                base_oid = '1.3.6.1.2.1.43.18.1.1'
                current_oid = base_oid
                alert_data = {}
                
                for _ in range(100):  # Safety limit
                    error_indication, error_status, error_index, var_binds = await next_cmd(
                        engine,
                        CommunityData(community),
                        target,
                        ContextData(),
                        ObjectType(ObjectIdentity(current_oid))
                    )
                    
                    if error_indication or error_status or not var_binds:
                        break
                    
                    oid_str = str(var_binds[0][0])
                    value = var_binds[0][1]
                    
                    if not oid_str.startswith(base_oid):
                        break
                    
                    parts = oid_str.split('.')
                    if len(parts) >= 13:
                        try:
                            column = int(parts[10])
                            dev_idx = int(parts[11])
                            alert_idx = int(parts[12])
                            
                            key = (dev_idx, alert_idx)
                            if key not in alert_data:
                                alert_data[key] = {'index': alert_idx}
                            
                            if column == 2:
                                alert_data[key]['severity_code'] = int(value)
                            elif column == 7:
                                alert_data[key]['code'] = int(value)
                            elif column == 8:
                                desc = str(value) if value else ''
                                if desc and desc != 'None':
                                    alert_data[key]['description'] = desc
                        except (ValueError, TypeError, IndexError):
                            pass
                    
                    current_oid = oid_str
                
                # Convert standard alerts to PrinterEvent objects
                for key, data in alert_data.items():
                    code = data.get('code', 0)
                    if code > 0:
                        severity_code = data.get('severity_code', 4)
                        severity = ALERT_SEVERITY.get(severity_code, 'warning')
                        message = STANDARD_ALERT_CODES.get(code, f"Alert Code {code}")
                        description = data.get('description', message)
                        logs.append(PrinterEvent(
                            code=code,
                            severity=severity,
                            message=message,
                            description=description
                        ))
            except Exception as e:
                logger.debug(f"prtAlertTable walk failed for {ip}: {e}")
            
            # 2. Check hrPrinterDetectedErrorState for basic status
            try:
                for oid in ['1.3.6.1.2.1.25.3.5.1.2.1', '1.3.6.1.2.1.25.3.5.1.2']:
                    error_indication, error_status, error_index, var_binds = await get_cmd(
                        engine,
                        CommunityData(community),
                        target,
                        ContextData(),
                        ObjectType(ObjectIdentity(oid))
                    )
                    
                    if not error_indication and not error_status and var_binds:
                        value = var_binds[0][1]
                        try:
                            error_bits = bytes(value) if not isinstance(value, bytes) else value
                            if len(error_bits) > 0 and error_bits[0] > 0:
                                byte0 = error_bits[0]
                                error_map = [
                                    (0x80, 505, 'warning', 'Low Paper', 'Paper supply is running low'),
                                    (0x40, 506, 'error', 'No Paper', 'Paper tray is empty'),
                                    (0x20, 503, 'warning', 'Low Toner', 'Toner supply is running low'),
                                    (0x10, 504, 'error', 'No Toner', 'Toner cartridge is empty'),
                                    (0x08, 501, 'warning', 'Door Open', 'A printer door or cover is open'),
                                    (0x04, 502, 'error', 'Paper Jam', 'Paper jam detected'),
                                    (0x02, 507, 'warning', 'Offline', 'Printer is offline'),
                                    (0x01, 508, 'info', 'Service Requested', 'Printer needs service attention'),
                                ]
                                for mask, code, sev, msg, desc in error_map:
                                    if byte0 & mask:
                                        if not any(l.code == code for l in logs):
                                            logs.append(PrinterEvent(code=code, severity=sev, message=msg, description=desc))
                                break
                        except (TypeError, IndexError):
                            pass
            except Exception as e:
                logger.debug(f"hrPrinterDetectedErrorState failed for {ip}: {e}")
            
            # 3. Query HP Event Log (HP printers only)
            # OID: 1.3.6.1.4.1.11.2.3.9.4.2.1.1.11.X.1.0 = event code, .X.2.0 = timestamp
            try:
                hp_base = '1.3.6.1.4.1.11.2.3.9.4.2.1.1.11'
                current_oid = hp_base
                hp_events = {}  # {index: {code: x, time: y}}
                
                for _ in range(200):  # HP logs can have many entries
                    error_indication, error_status, error_index, var_binds = await next_cmd(
                        engine,
                        CommunityData(community),
                        target,
                        ContextData(),
                        ObjectType(ObjectIdentity(current_oid))
                    )
                    
                    if error_indication or error_status or not var_binds:
                        break
                    
                    oid_str = str(var_binds[0][0])
                    value = var_binds[0][1]
                    
                    if not oid_str.startswith(hp_base):
                        break
                    
                    # Parse: base.index.column.0
                    suffix = oid_str[len(hp_base)+1:]  # Get suffix after base
                    parts = suffix.split('.')
                    if len(parts) >= 3:
                        try:
                            idx = int(parts[0])  # Event index
                            col = int(parts[1])  # Column (1=code, 2=time)
                            
                            if idx not in hp_events:
                                hp_events[idx] = {}
                            
                            if col == 1:
                                hp_events[idx]['code'] = int(value)
                            elif col == 2:
                                hp_events[idx]['time_cs'] = int(value)  # centiseconds
                        except (ValueError, TypeError):
                            pass
                    
                    current_oid = oid_str
                
                # Get current sysUpTime to calculate relative times
                current_uptime_cs = 0
                try:
                    error_indication, error_status, error_index, var_binds = await get_cmd(
                        engine,
                        CommunityData(community),
                        target,
                        ContextData(),
                        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0'))  # sysUpTime
                    )
                    if not error_indication and not error_status and var_binds:
                        current_uptime_cs = int(var_binds[0][1])
                except:
                    pass
                
                # Convert HP events to PrinterEvent objects
                for idx in sorted(hp_events.keys(), reverse=True):  # Most recent first
                    data = hp_events[idx]
                    code = data.get('code', 0)
                    if code > 0:
                        if code in HP_EVENT_CODES:
                            severity, message, description = HP_EVENT_CODES[code]
                        else:
                            # Unknown code - use smart categorization by range
                            # HP doesn't provide text descriptions via SNMP, only codes
                            severity, message, description = categorize_hp_event_code(code)
                        
                        # Calculate time display
                        time_display = ''
                        if 'time_cs' in data and current_uptime_cs > 0:
                            event_time_cs = data['time_cs']
                            # Time ago = current uptime - event time
                            ago_cs = current_uptime_cs - event_time_cs
                            if ago_cs >= 0:
                                ago_sec = ago_cs // 100
                                if ago_sec < 60:
                                    time_display = f'{ago_sec}s ago'
                                elif ago_sec < 3600:
                                    time_display = f'{ago_sec // 60}m ago'
                                elif ago_sec < 86400:
                                    hours = ago_sec // 3600
                                    mins = (ago_sec % 3600) // 60
                                    time_display = f'{hours}h {mins}m ago'
                                else:
                                    days = ago_sec // 86400
                                    hours = (ago_sec % 86400) // 3600
                                    time_display = f'{days}d {hours}h ago'
                            else:
                                # Event is in the future? Just show uptime
                                uptime_sec = event_time_cs // 100
                                hours = uptime_sec // 3600
                                mins = (uptime_sec % 3600) // 60
                                time_display = f'@{hours}h {mins}m'
                        
                        logs.append(PrinterEvent(
                            code=code,
                            severity=severity,
                            message=message,
                            description=description,
                            time_display=time_display
                        ))
            except Exception as e:
                logger.debug(f"HP event log query failed for {ip}: {e}")
                
        except ImportError as e:
            logger.warning(f"pysnmp import error: {e}")
        except Exception as e:
            logger.error(f"Error getting logs for {ip}: {e}")
        
        return logs
    
    # Run the async function
    try:
        loop = asyncio.new_event_loop()
        logs = loop.run_until_complete(collect_logs())
        loop.close()
    except Exception as e:
        logger.error(f"Asyncio error for {ip}: {e}")
        logs = []
    
    # Sort by severity (critical first) then by code
    severity_order = {'critical': 0, 'error': 1, 'warning': 2, 'info': 3, 'other': 4}
    logs.sort(key=lambda x: (severity_order.get(x.severity, 5), x.code))
    
    return logs


# Backwards compatibility alias
def get_errors(ip: str) -> List[PrinterEvent]:
    """Alias for get_logs."""
    return get_logs(ip)
