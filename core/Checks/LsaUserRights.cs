using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace CISAudit.Core.Checks;

/// <summary>
/// Enumerates the SIDs that hold a given Windows privilege via the LSA API.
/// This is the authoritative source for "who has SeXxxPrivilege" — far better
/// than secedit /export, which only emits the LOCAL policy override and stays
/// silent when the right is at OS default or comes solely from a domain GPO.
/// </summary>
internal static class LsaUserRights
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_ENUMERATION_INFORMATION
    {
        public IntPtr Sid;
    }

    [DllImport("advapi32.dll", PreserveSig = true)]
    private static extern uint LsaOpenPolicy(IntPtr SystemName, ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
                                             uint DesiredAccess, out IntPtr PolicyHandle);

    [DllImport("advapi32.dll", PreserveSig = true)]
    private static extern uint LsaEnumerateAccountsWithUserRight(IntPtr PolicyHandle,
                                                                  ref LSA_UNICODE_STRING UserRight,
                                                                  out IntPtr Buffer, out int CountReturned);

    [DllImport("advapi32.dll", PreserveSig = true)]
    private static extern uint LsaFreeMemory(IntPtr Buffer);

    [DllImport("advapi32.dll", PreserveSig = true)]
    private static extern uint LsaClose(IntPtr PolicyHandle);

    [DllImport("advapi32.dll", PreserveSig = false)]
    private static extern int LsaNtStatusToWinError(uint status);

    private const uint POLICY_LOOKUP_NAMES           = 0x00000800;
    private const uint POLICY_VIEW_LOCAL_INFORMATION = 0x00000001;
    private const uint STATUS_SUCCESS                = 0x00000000;
    private const uint STATUS_OBJECT_NAME_NOT_FOUND  = 0xC0000034;
    private const uint STATUS_NO_MORE_ENTRIES        = 0x8000001A;

    /// <summary>
    /// Returns the SIDs holding <paramref name="privilegeName"/> (e.g. "SeTcbPrivilege").
    /// Returns an empty list if no account holds the right. Throws on failure.
    /// </summary>
    public static List<SecurityIdentifier> EnumerateAccounts(string privilegeName)
    {
        var attrs = new LSA_OBJECT_ATTRIBUTES { Length = Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>() };
        var status = LsaOpenPolicy(IntPtr.Zero, ref attrs,
                                   POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION,
                                   out var policyHandle);
        if (status != STATUS_SUCCESS)
            throw new Win32Exception(LsaNtStatusToWinError(status), "LsaOpenPolicy failed");

        try
        {
            // LSA_UNICODE_STRING buffer must NOT be null-terminated; Length is in bytes.
            var bytes = (ushort)(privilegeName.Length * sizeof(char));
            var bufPtr = Marshal.StringToHGlobalUni(privilegeName);
            try
            {
                var lsaStr = new LSA_UNICODE_STRING
                {
                    Length = bytes,
                    MaximumLength = (ushort)(bytes + sizeof(char)),
                    Buffer = bufPtr
                };

                status = LsaEnumerateAccountsWithUserRight(policyHandle, ref lsaStr,
                                                            out var enumBuffer, out var count);
                if (status == STATUS_NO_MORE_ENTRIES || status == STATUS_OBJECT_NAME_NOT_FOUND)
                    return new List<SecurityIdentifier>(0);
                if (status != STATUS_SUCCESS)
                    throw new Win32Exception(LsaNtStatusToWinError(status),
                        $"LsaEnumerateAccountsWithUserRight failed for {privilegeName}");

                try
                {
                    var sids = new List<SecurityIdentifier>(count);
                    var stride = Marshal.SizeOf<LSA_ENUMERATION_INFORMATION>();
                    for (var i = 0; i < count; i++)
                    {
                        var entry = Marshal.PtrToStructure<LSA_ENUMERATION_INFORMATION>(
                            IntPtr.Add(enumBuffer, i * stride));
                        sids.Add(new SecurityIdentifier(entry.Sid));
                    }
                    return sids;
                }
                finally
                {
                    LsaFreeMemory(enumBuffer);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(bufPtr);
            }
        }
        finally
        {
            LsaClose(policyHandle);
        }
    }
}
