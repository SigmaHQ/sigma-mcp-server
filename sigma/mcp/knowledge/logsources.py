"""Curated knowledge about common Sigma log sources.

Each entry describes one logsource: what it records, its most useful fields,
relevant event IDs and practical tips for writing detections.  The rule index
adds how often SigmaHQ rules use the logsource and its fields (see
:func:`sigma.mcp.tools.rules.get_logsource_info`).
"""

from __future__ import annotations

from typing import Any

LOGSOURCES: dict[str, dict[str, Any]] = {
    "process_creation_windows": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "description": "Windows process creation events. The most commonly used logsource. "
        "Normalizes Sysmon Event ID 1, Windows Security Event 4688, and ETW sources.",
        "fields": {
            "Image": "Full path to the executed binary (e.g. C:\\Windows\\System32\\cmd.exe)",
            "OriginalFileName": "Original filename from PE header – stable even when renamed",
            "CommandLine": "Full command line including arguments",
            "CurrentDirectory": "Working directory of the new process",
            "ParentImage": "Full path of the parent process",
            "ParentCommandLine": "Command line of the parent process",
            "ParentProcessId": "PID of the parent",
            "ProcessId": "PID of the new process",
            "User": "Account name that launched the process (DOMAIN\\user)",
            "IntegrityLevel": "Process integrity level: Low, Medium, High, System",
            "Hashes": "Process image hashes (MD5, SHA1, SHA256, IMPHASH)",
            "LogonId": "Logon session identifier",
        },
        "tips": [
            "Use OriginalFileName instead of Image to detect renamed binaries.",
            "Use Image|endswith: '\\\\tool.exe' rather than Image|contains: 'tool'.",
            "CommandLine matching is very powerful but can be noisy – add parent process checks.",
            "IntegrityLevel: High or System indicates elevated execution.",
        ],
    },
    "process_creation_linux": {
        "logsource": {"category": "process_creation", "product": "linux"},
        "description": "Linux process creation events from auditd, syslog, or EDR.",
        "fields": {
            "Image": "Full path to the binary (e.g. /usr/bin/curl)",
            "CommandLine": "Full command line",
            "ParentImage": "Full path to the parent process",
            "ParentCommandLine": "Parent command line",
            "User": "Username that ran the process",
        },
        "tips": ["Use Image|endswith: '/tool' pattern for Linux paths."],
    },
    "security_windows": {
        "logsource": {"service": "security", "product": "windows"},
        "description": "Windows Security event log. Contains authentication, access control, and audit events.",
        "event_ids": {
            "1102": "Security audit log cleared",
            "4624": "Successful logon. Fields: LogonType, SubjectUserName, TargetUserName, IpAddress, AuthenticationPackageName, WorkstationName",
            "4625": "Failed logon attempt. Fields: LogonType, SubjectUserName, TargetUserName, FailureReason, IpAddress",
            "4634": "Account logoff",
            "4648": "Logon using explicit credentials (runas). Fields: SubjectUserName, TargetUserName, TargetServerName, ProcessName",
            "4656": "Object handle requested",
            "4657": "Registry value modified. Fields: ObjectName, NewValue, OldValue, SubjectUserName",
            "4663": "Object access. Fields: ObjectName, AccessMask, SubjectUserName",
            "4670": "Object permissions changed",
            "4672": "Special privileges (SeDebugPrivilege etc.) assigned at logon. Fields: SubjectUserName, PrivilegeList",
            "4688": "Process creation (legacy – prefer category: process_creation). Fields: NewProcessName, CommandLine, SubjectUserName, ParentProcessName",
            "4697": "Service installed via SCM. Fields: ServiceName, ServiceFileName, ServiceType, StartType",
            "4698": "Scheduled task created. Fields: TaskName, SubjectUserName, TaskContent",
            "4699": "Scheduled task deleted",
            "4702": "Scheduled task updated",
            "4703": "Token right adjusted",
            "4719": "System audit policy changed",
            "4720": "User account created. Fields: TargetUserName, SubjectUserName",
            "4722": "User account enabled",
            "4724": "Password reset attempt",
            "4725": "User account disabled",
            "4726": "User account deleted",
            "4728": "Member added to security-enabled global group",
            "4729": "Member removed from security-enabled global group",
            "4732": "Member added to security-enabled local group",
            "4733": "Member removed from security-enabled local group",
            "4735": "Security-enabled local group changed",
            "4738": "User account changed",
            "4740": "User account locked out",
            "4756": "Member added to security-enabled universal group",
            "4768": "Kerberos TGT requested. Fields: TargetUserName, IpAddress, Status, TicketEncryptionType",
            "4769": "Kerberos service ticket requested. Fields: TargetUserName, ServiceName, IpAddress, TicketEncryptionType, TicketOptions",
            "4776": "NTLM credential validation. Fields: TargetUserName, Workstation, Status",
            "4946": "Windows Firewall rule added",
            "5140": "Network share accessed. Fields: ShareName, IpAddress, SubjectUserName",
            "5142": "Network share object added",
            "5145": "Network share object access check. Fields: ShareName, RelativeTargetName, IpAddress",
            "7045": "New service installed (also in System log). Fields: ServiceName, ImagePath, ServiceType, StartType",
        },
        "fields": {
            "EventID": "Windows event identifier (integer)",
            "SubjectUserName": "Account that performed the action",
            "SubjectDomainName": "Domain of the subject account",
            "TargetUserName": "Account targeted by the action",
            "TargetDomainName": "Domain of the target account",
            "LogonType": "2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 8=NetworkCleartext, 9=NewCredentials, 10=RemoteInteractive",
            "IpAddress": "Source IP address",
            "IpPort": "Source port",
        },
    },
    "system_windows": {
        "logsource": {"service": "system", "product": "windows"},
        "description": "Windows System event log.",
        "event_ids": {
            "104": "Event log cleared (System channel)",
            "7034": "Service crashed unexpectedly",
            "7036": "Service state change. Fields: ServiceName, param2 (running/stopped)",
            "7040": "Service start type changed. Fields: ServiceName, param3 (boot/auto/demand/disabled)",
            "7045": "New service installed. Fields: ServiceName, ImagePath, ServiceType, StartType, AccountName",
        },
        "fields": {
            "EventID": "Event identifier",
            "ServiceName": "Name of the Windows service",
            "ImagePath": "Executable path or command for the service",
        },
    },
    "powershell_script": {
        "logsource": {"category": "ps_script", "product": "windows"},
        "description": "PowerShell Script Block Logging (Event 4104). Requires HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging enabled.",
        "fields": {
            "ScriptBlockText": "The full PowerShell script block content",
            "ScriptBlockId": "GUID identifying the script block",
            "Path": "Path to the script file if executed from file",
            "MessageNumber": "Part number for multi-part script blocks",
            "MessageTotal": "Total number of parts",
        },
        "tips": [
            "ScriptBlockText|contains is very powerful for detecting specific commands.",
            "Watch for obfuscation patterns: [char], iex, -enc, frombase64string.",
        ],
    },
    "powershell_module": {
        "logsource": {"category": "ps_module", "product": "windows"},
        "description": "PowerShell Module Logging (Event 4103).",
        "fields": {
            "Payload": "Module logging payload",
            "CommandName": "Name of the command",
        },
    },
    "powershell_classic": {
        "logsource": {"category": "ps_classic_start", "product": "windows"},
        "description": "PowerShell classic provider start events (Events 400, 403, 600).",
        "fields": {
            "HostApplication": "How PowerShell was invoked",
            "EngineVersion": "PowerShell engine version",
        },
    },
    "network_connection": {
        "logsource": {"category": "network_connection", "product": "windows"},
        "description": "Network connection events (Sysmon Event 3). Tracks outbound TCP/UDP connections.",
        "fields": {
            "Image": "Process making the connection",
            "Initiated": "true if initiated by the process",
            "Protocol": "tcp or udp",
            "SourceIp": "Source IP address",
            "SourcePort": "Source port",
            "DestinationIp": "Destination IP address",
            "DestinationPort": "Destination port (integer)",
            "DestinationHostname": "Destination hostname if resolved",
            "User": "User account",
        },
        "tips": [
            "Filter on Initiated: 'true' for outbound connections.",
            "DestinationPort: 443 for HTTPS, 80 for HTTP, 4444/4445 for common C2.",
        ],
    },
    "dns_query": {
        "logsource": {"category": "dns_query", "product": "windows"},
        "description": "DNS query events (Sysmon Event 22). Tracks DNS lookups by processes.",
        "fields": {
            "Image": "Process making the DNS query",
            "QueryName": "Domain name being queried",
            "QueryResults": "DNS response (IP addresses)",
            "QueryStatus": "0 = success",
        },
    },
    "file_event": {
        "logsource": {"category": "file_event", "product": "windows"},
        "description": "File creation events (Sysmon Event 11). Only tracks new file creation, not modifications.",
        "fields": {
            "Image": "Process that created the file",
            "TargetFilename": "Full path of the created file",
            "Hashes": "File hashes",
            "CreationUtcTime": "File creation timestamp",
            "User": "User account",
        },
    },
    "file_change": {
        "logsource": {"category": "file_change", "product": "windows"},
        "description": "File modification events (Sysmon Event 2 – file creation time change).",
        "fields": {
            "Image": "Process that changed the file",
            "TargetFilename": "File path",
            "CreationUtcTime": "New creation time",
            "PreviousCreationUtcTime": "Old creation time",
        },
    },
    "file_rename": {
        "logsource": {"category": "file_rename", "product": "windows"},
        "description": "File rename events.",
        "fields": {
            "Image": "Process performing the rename",
            "TargetFilename": "New filename",
            "OldFilename": "Original filename",
        },
    },
    "file_delete": {
        "logsource": {"category": "file_delete", "product": "windows"},
        "description": "File deletion events.",
        "fields": {
            "Image": "Process deleting the file",
            "TargetFilename": "Deleted file path",
        },
    },
    "registry_event": {
        "logsource": {"category": "registry_event", "product": "windows"},
        "description": "Registry modification events (Sysmon Events 12, 13, 14). Use specific categories below when possible.",
        "fields": {
            "EventType": "CreateKey, DeleteKey, SetValue, DeleteValue, RenameKey",
            "Image": "Process modifying the registry",
            "TargetObject": "Full registry key path (e.g. HKLM\\Software\\...)",
            "Details": "New value data (for SetValue)",
        },
    },
    "registry_add": {
        "logsource": {"category": "registry_add", "product": "windows"},
        "description": "Registry key/value creation (Sysmon Event 12, CreateKey).",
        "fields": {
            "Image": "Process creating the key",
            "TargetObject": "Registry key path",
        },
    },
    "registry_set": {
        "logsource": {"category": "registry_set", "product": "windows"},
        "description": "Registry value set events (Sysmon Event 13, SetValue).",
        "fields": {
            "Image": "Process setting the value",
            "TargetObject": "Full path including value name",
            "Details": "New value data",
        },
        "tips": [
            "Common persistence keys: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<binary>",
        ],
    },
    "registry_delete": {
        "logsource": {"category": "registry_delete", "product": "windows"},
        "description": "Registry key/value deletion (Sysmon Event 12/14).",
        "fields": {
            "Image": "Process deleting",
            "TargetObject": "Deleted key/value path",
        },
    },
    "image_load": {
        "logsource": {"category": "image_load", "product": "windows"},
        "description": "DLL/driver image loading events (Sysmon Event 7). Very noisy – add tight filters.",
        "fields": {
            "Image": "Process loading the DLL",
            "ImageLoaded": "Full path of the loaded image/DLL",
            "Hashes": "Hashes of the loaded image",
            "Signed": "true/false",
            "Signature": "Certificate subject",
            "SignatureStatus": "Valid, Expired, Revoked, Unchecked",
        },
    },
    "driver_load": {
        "logsource": {"category": "driver_load", "product": "windows"},
        "description": "Kernel driver loading events (Sysmon Event 6).",
        "fields": {
            "ImageLoaded": "Full path of the driver",
            "Hashes": "Driver hashes",
            "Signed": "true/false",
            "Signature": "Certificate subject",
        },
    },
    "create_remote_thread": {
        "logsource": {"category": "create_remote_thread", "product": "windows"},
        "description": "Remote thread creation (Sysmon Event 8). Indicative of code injection.",
        "fields": {
            "SourceImage": "Process creating the thread",
            "TargetImage": "Process in which the thread is created",
            "TargetProcessId": "PID of the target process",
            "StartAddress": "Memory address where thread starts",
            "StartFunction": "Function name if resolved",
            "StartModule": "Module containing the start address",
        },
    },
    "process_access": {
        "logsource": {"category": "process_access", "product": "windows"},
        "description": "Process memory access (Sysmon Event 10). Indicative of credential dumping, injection.",
        "fields": {
            "SourceImage": "Process requesting access",
            "TargetImage": "Target process",
            "GrantedAccess": "Access rights mask (hex)",
            "CallTrace": "Call stack leading to OpenProcess",
        },
        "tips": [
            "GrantedAccess: '0x1010' or '0x1fffff' often indicates credential dumping from lsass.exe.",
        ],
    },
    "pipe_created": {
        "logsource": {"category": "pipe_created", "product": "windows"},
        "description": "Named pipe creation (Sysmon Events 17/18). Used by many C2 frameworks.",
        "fields": {
            "Image": "Process creating or connecting to the pipe",
            "PipeName": "Named pipe path (e.g. \\\\pipe\\\\metsvc)",
        },
    },
    "windefend": {
        "logsource": {"service": "windefend", "product": "windows"},
        "description": "Windows Defender / Microsoft Antivirus events.",
        "event_ids": {
            "1006": "Malware scan started",
            "1116": "Malware detected. Fields: ThreatName, Severity, Path, DetectionUser",
            "1117": "Malware action taken. Fields: ThreatName, ActionSuccess",
            "1118": "Malware cleanup started",
            "1119": "Malware cleanup succeeded",
            "5001": "Real-time protection disabled",
            "5004": "Real-time protection configuration changed",
        },
    },
    "applocker": {
        "logsource": {"service": "applocker", "product": "windows"},
        "description": "AppLocker and WDAC (Windows Defender Application Control) events.",
        "event_ids": {
            "8003": "Executable was allowed",
            "8004": "Executable was blocked",
            "8006": "Script/MSI was allowed",
            "8007": "Script/MSI was blocked",
        },
        "fields": {
            "PolicyName": "AppLocker policy",
            "FilePath": "Path of the executable/script",
        },
    },
    "taskscheduler": {
        "logsource": {"service": "taskscheduler", "product": "windows"},
        "description": "Windows Task Scheduler operational events.",
        "event_ids": {
            "106": "Task registered",
            "140": "Task updated",
            "141": "Task deleted",
            "200": "Task action started",
            "201": "Task action completed",
        },
        "fields": {
            "TaskName": "Full task path (e.g. \\Microsoft\\Windows\\...)",
            "SubjectUserName": "User registering the task",
            "ActionName": "Executable called by the task",
        },
    },
    "firewall_windows": {
        "logsource": {"service": "firewall-as", "product": "windows"},
        "description": "Windows Firewall with Advanced Security events.",
        "event_ids": {
            "2004": "Firewall rule added",
            "2005": "Firewall rule changed",
            "2006": "Firewall rule deleted",
        },
        "fields": {
            "RuleName": "Name of the firewall rule",
            "Direction": "In/Out",
            "Protocol": "TCP/UDP",
            "LocalPort": "Local port",
            "RemotePort": "Remote port",
            "ApplicationPath": "Application associated with the rule",
        },
    },
    "proxy": {
        "logsource": {"category": "proxy"},
        "description": "Web proxy / HTTP access logs.",
        "fields": {
            "cs-host": "Destination hostname",
            "cs-uri-query": "URI query string",
            "cs-uri-stem": "URI path",
            "c-ip": "Client IP",
            "cs-username": "Authenticated username",
            "cs(User-Agent)": "HTTP User-Agent header",
            "cs-method": "HTTP method (GET, POST, etc.)",
            "sc-status": "HTTP response status code",
            "cs-bytes": "Bytes sent",
        },
    },
    "webserver": {
        "logsource": {"category": "webserver"},
        "description": "Web server access logs (IIS, Apache, Nginx).",
        "fields": {
            "cs-method": "HTTP method",
            "cs-uri-query": "URL query string",
            "cs-uri-stem": "URL path",
            "c-ip": "Client IP",
            "cs(User-Agent)": "User-Agent header",
            "sc-status": "Response status code",
        },
    },
    "aws_cloudtrail": {
        "logsource": {"product": "aws", "service": "cloudtrail"},
        "description": "AWS CloudTrail API call logs.",
        "fields": {
            "eventSource": "AWS service endpoint (e.g. s3.amazonaws.com)",
            "eventName": "API call name (e.g. PutObject, CreateUser)",
            "userIdentity.type": "Root, IAMUser, AssumedRole, FederatedUser",
            "userIdentity.userName": "IAM username",
            "userIdentity.arn": "IAM ARN",
            "sourceIPAddress": "Caller IP address",
            "requestParameters": "API call parameters",
            "errorCode": "Error code if call failed",
        },
    },
    "azure_activity": {
        "logsource": {"product": "azure", "service": "activitylogs"},
        "description": "Azure Activity Log (subscription-level operations).",
        "fields": {
            "operationName": "Azure resource operation (e.g. Microsoft.Authorization/roleAssignments/write)",
            "resultType": "Success, Failure, Start",
            "identity": "Caller identity",
            "callerIpAddress": "Caller IP",
            "level": "Critical, Error, Warning, Informational",
        },
    },
    "linux_auth": {
        "logsource": {"service": "auth", "product": "linux"},
        "description": "Linux authentication events (/var/log/auth.log, /var/log/secure).",
        "tips": [
            "SSH login events, sudo usage, su attempts, PAM events.",
            "Common patterns: 'Accepted password', 'Failed password', 'sudo:', 'su:'",
        ],
    },
    "linux_syslog": {
        "logsource": {"service": "syslog", "product": "linux"},
        "description": "General Linux system log.",
        "tips": ["Kernel messages, daemon events, cron jobs."],
    },
}
