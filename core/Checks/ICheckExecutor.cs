using CISAudit.Core.Models;

namespace CISAudit.Core.Checks;

public interface ICheckExecutor
{
    CheckKind Kind { get; }
    CheckResult Evaluate(ControlDefinition def, AuditContext ctx);
}

/// <summary>Shared runtime context — cached expensive lookups, environment flags.</summary>
public sealed class AuditContext
{
    public Lazy<SecPolSnapshot> SecPol { get; }
    public Lazy<AuditPolSnapshot> AuditPol { get; }
    public bool IsElevated { get; }
    public bool IsDomainJoined { get; }

    public AuditContext(bool isElevated, bool isDomainJoined,
                        Func<SecPolSnapshot> secPolLoader,
                        Func<AuditPolSnapshot> auditPolLoader)
    {
        IsElevated = isElevated;
        IsDomainJoined = isDomainJoined;
        SecPol = new Lazy<SecPolSnapshot>(secPolLoader);
        AuditPol = new Lazy<AuditPolSnapshot>(auditPolLoader);
    }
}
