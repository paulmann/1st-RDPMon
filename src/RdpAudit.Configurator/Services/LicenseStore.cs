// File:    src/RdpAudit.Configurator/Services/LicenseStore.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Local persistence and (stub) activation of the product license key. The current build
//          accepts ANY non-empty key offline and stores it under HKCU so it survives restarts; the
//          production activation path (an HTTP POST to the activation endpoint expecting "1"/"0") is
//          provided as a ready-to-enable, fully documented method.
// Depends: Microsoft.Win32.Registry (HKCU persistence), System.Net.Http (production activation path)
// Extends: To switch from the offline stub to server-side activation, call ActivateOnlineAsync from
//          OverviewPage.LicensePanel instead of ActivateOffline, and remove the stub. To relocate the
//          stored key (e.g. to a file under %ProgramData%), change RegistrySubKey / Load / Save only.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.2

using System.Runtime.Versioning;
using Microsoft.Win32;

namespace RdpAudit.Configurator.Services;

/// <summary>Local persistence and stub activation of the product license key.</summary>
[SupportedOSPlatform("windows")]
public sealed class LicenseStore
{
	// ── Fields & Constants ───────────────────────────────────────────────────────
	private const string RegistrySubKey = @"Software\RdpAudit";
	private const string KeyValueName = "LicenseKey";

	/// <summary>Production activation endpoint. The server is expected to answer with a plain body of
	/// "1" (activation succeeded) or "0" (rejected) for a form POST of <c>key=[key]</c>.</summary>
	private const string ActivationEndpoint = "https://activate.3389port.com/";

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Reads the persisted license key, or returns <c>null</c> when none is stored.</summary>
	public string? Load()
	{
		try
		{
			using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RegistrySubKey, writable: false);
			string? value = key?.GetValue(KeyValueName) as string;
			return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
		}
		catch (Exception)
		{
			// Treat any registry read failure as "no license" — the UI then shows the input field.
			return null;
		}
	}

	/// <summary>Persists the license key under HKCU. Overwrites any previously stored value.</summary>
	public void Save(string licenseKey)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(licenseKey);

		using RegistryKey key = Registry.CurrentUser.CreateSubKey(RegistrySubKey, writable: true);
		key.SetValue(KeyValueName, licenseKey.Trim(), RegistryValueKind.String);
	}

	/// <summary>Removes the persisted license key, returning the UI to the unactivated state.</summary>
	public void Clear()
	{
		try
		{
			using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RegistrySubKey, writable: true);
			if (key?.GetValue(KeyValueName) is not null)
			{
				key.DeleteValue(KeyValueName, throwOnMissingValue: false);
			}
		}
		catch (Exception)
		{
			// Best-effort delete: if the value is already gone the UI state is correct regardless.
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	/// <summary>STUB activation for the current build: accepts any non-empty key and persists it.
	/// Always succeeds for a non-empty key. Replace the call site with <see cref="ActivateOnlineAsync"/>
	/// to enforce server-side activation.</summary>
	public bool ActivateOffline(string licenseKey)
	{
		if (string.IsNullOrWhiteSpace(licenseKey))
		{
			return false;
		}

		Save(licenseKey);
		return true;
	}

	// ── Production Activation (ready to enable) ──────────────────────────────────

	/// <summary>PRODUCTION activation path (currently unused while the offline stub is active). Sends a
	/// form-encoded POST of <c>key=[key]</c> to the activation endpoint and treats a response body of
	/// "1" as success and "0" (or anything else) as failure. On success the key is persisted locally so
	/// subsequent launches start activated. Honors the supplied <paramref name="ct"/>.</summary>
	public async Task<bool> ActivateOnlineAsync(string licenseKey, CancellationToken ct = default)
	{
		if (string.IsNullOrWhiteSpace(licenseKey))
		{
			return false;
		}

		using HttpClient http = new()
		{
			Timeout = TimeSpan.FromSeconds(15),
		};

		using FormUrlEncodedContent content = new(new[]
		{
			new KeyValuePair<string, string>("key", licenseKey.Trim()),
		});

		using HttpResponseMessage response =
			await http.PostAsync(new Uri(ActivationEndpoint), content, ct).ConfigureAwait(false);
		response.EnsureSuccessStatusCode();

		string body = (await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false)).Trim();
		bool activated = string.Equals(body, "1", StringComparison.Ordinal);
		if (activated)
		{
			Save(licenseKey);
		}

		return activated;
	}
}
