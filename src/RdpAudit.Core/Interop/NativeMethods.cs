// File:    src/RdpAudit.Core/Interop/NativeMethods.cs
// Module:  RdpAudit.Core.Interop
// Purpose: Source-generated P/Invoke declarations only — no logic.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RdpAudit.Core.Interop;

/// <summary>Source-generated P/Invoke declarations only — no logic.</summary>
internal static partial class NativeMethods
{
	internal const uint TOKEN_QUERY = 0x0008;

	[LibraryImport("advapi32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool OpenProcessToken(
		SafeProcessHandle processHandle,
		uint desiredAccess,
		out SafeAccessTokenHandle tokenHandle);
}
