// File:    src/RdpAudit.Service/AppSettingsTemplate.cs
// Module:  RdpAudit.Service
// Purpose: Default appsettings.json template written on first service start.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Service;

/// <summary>Default appsettings.json template written on first service start.</summary>
public static class AppSettingsTemplate
{
	public const string Default = """
{
	"Serilog": {
		"MinimumLevel": {
			"Default": "Information",
			"Override": {
				"Microsoft": "Warning",
				"Microsoft.EntityFrameworkCore": "Warning"
			}
		}
	},
	"RdpAudit": {
		"Monitoring": {
			"FilterLocalAddresses": true,
			"TrackProcessCreation": true,
			"TrackScheduledTasks": true,
			"TrackAccountChanges": true,
			"TrackKerberos": true,
			"TrackObjectAccess": true,
			"BatchSize": 100,
			"BatchTimeoutMilliseconds": 500,
			"ChannelCapacity": 50000
		},
		"Alerts": {
			"EnableBruteForceDetection": true,
			"BruteForceThreshold": 10,
			"BruteForceWindowMinutes": 5,
			"BruteForceNtlmThreshold": 20,
			"KerberosSprayThreshold": 20,
			"RapidReconnectSeconds": 30,
			"UnknownIpSuccessFailureThreshold": 5,
			"OffHoursAlertEnabled": true,
			"BusinessHoursStart": "08:00:00",
			"BusinessHoursEnd": "20:00:00",
			"KerberosExpectedEncryptionType": "0x12",
			"WhitelistIps": [],
			"WhitelistUsers": []
		},
		"Firewall": {
			"AutoBlockBruteForce": false,
			"AutoBlockThreshold": 50,
			"BlockRuleName": "RdpAudit-Block"
		},
		"Storage": {
			"DatabasePath": "",
			"EventRetentionDays": 365,
			"LogRetentionDays": 90,
			"AlertRetentionDays": 730
		},
		"Diagnostics": {
			"DebugMode": false,
			"LogEventXmlAtDebug": false,
			"LogChannelDrops": true,
			"LogAlertEvaluationTimings": false
		}
	}
}
""";
}
