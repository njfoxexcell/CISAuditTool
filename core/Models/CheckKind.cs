namespace CISAudit.Core.Models;

public enum CheckKind
{
    Registry,
    SecurityPolicy,   // secedit / Local Security Policy (Account/Local Policies & Security Options)
    AuditPolicy,      // auditpol / Advanced Audit Policy
    UserRight,        // SeXxxPrivilege assignments
    Service,          // Win32 service start type
    WindowsFeature,   // optional feature presence / state
    Wmi,              // generic CIM/WMI query (used for BitLocker, TPM, etc.)
    Manual            // documented but not automatable -> excluded from score
}
