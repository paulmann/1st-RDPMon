// File:    src/RdpAudit.Core/Ipc/IpcCommand.cs
// Module:  RdpAudit.Core.Ipc
// Purpose: Enumeration of IPC commands sent from Configurator to Service.
// Extends: System.Enum
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Ipc;

/// <summary>Enumeration of IPC commands sent from Configurator to Service.</summary>
public enum IpcCommand
{
	Ping = 0,
	GetStatus = 1,
	GetRecentEvents = 2,
	GetRecentAlerts = 3,
	GetAddresses = 4,
	GetSessions = 5,
	AcknowledgeAlert = 6,
	BlockAddress = 7,
	UnblockAddress = 8,
	GetSettings = 9,
	SaveSettings = 10,
}
