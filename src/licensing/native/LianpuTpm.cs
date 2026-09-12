using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

// This helper deliberately has no provider, key-name, deletion, export-private-key,
// TPM-clear, import-key, or elevation command. Test names are compile-time only.
internal static class LianpuTpm
{
    private const string Provider = "Microsoft Platform Crypto Provider";
#if LIANPU_ISOLATED_TEST
    private const string KeyName = "Lianpu.Desktop.Licensing.IsolatedTest.DeviceKey.v1.20260911";
    private const string DirectoryName = "LicensingIsolatedTest";
    private const bool TestMode = true;
#else
    private const string KeyName = "Lianpu.Desktop.Licensing.DeviceKey.v1";
    private const string DirectoryName = "Licensing";
    private const bool TestMode = false;
#endif
    private const uint Machine = 0x20, Silent = 0x40, SignUsage = 0x2;
    private const uint DaclInformation = 4, OwnerInformation = 1, PersistProperty = 0x80000000;
    private const uint GenericRead = 0x80000000, GenericWrite = 0x40000000, GenericAll = 0x10000000;
    private const uint KeyRead = 0x00020089, KeyWrite = 0x00020112, KeyFull = 0x001F019B;
    private const string SystemSid = "S-1-5-18", AdministratorsSid = "S-1-5-32-544", UsersSid = "S-1-5-32-545";
    private const int MaximumChallengeBytes = 16384;
    private const int MaximumEncodedCharacters = 21846;
    private static readonly string StoragePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Lianpu", DirectoryName, "v1");
    private static TpmInfo device;

    [StructLayout(LayoutKind.Sequential)]
    private struct TpmInfo { public uint structVersion, tpmVersion, tpmInterfaceType, tpmImpRevision; }

    [DllImport("tbs.dll", ExactSpelling = true)] private static extern uint Tbsi_GetDeviceInfo(uint size, ref TpmInfo info);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern uint NCryptOpenStorageProvider(out IntPtr provider, string name, uint flags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern uint NCryptOpenKey(IntPtr provider, out IntPtr key, string name, uint legacySpec, uint flags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern uint NCryptCreatePersistedKey(IntPtr provider, out IntPtr key, string algorithm, string name, uint legacySpec, uint flags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern uint NCryptSetProperty(IntPtr handle, string property, byte[] input, int size, uint flags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern uint NCryptGetProperty(IntPtr handle, string property, byte[] output, int size, out int result, uint flags);
    [DllImport("ncrypt.dll", ExactSpelling = true)] private static extern uint NCryptFinalizeKey(IntPtr key, uint flags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern uint NCryptExportKey(IntPtr key, IntPtr exportKey, string blobType, IntPtr parameters, byte[] output, int size, out int result, uint flags);
    [DllImport("ncrypt.dll", ExactSpelling = true)] private static extern uint NCryptSignHash(IntPtr key, IntPtr padding, byte[] hash, int hashSize, byte[] signature, int signatureSize, out int result, uint flags);
    [DllImport("ncrypt.dll", ExactSpelling = true)] private static extern uint NCryptVerifySignature(IntPtr key, IntPtr padding, byte[] hash, int hashSize, byte[] signature, int signatureSize, uint flags);
    [DllImport("ncrypt.dll", ExactSpelling = true)] private static extern uint NCryptFreeObject(IntPtr handle);

    internal sealed class Failure : Exception
    {
        internal readonly string State, Code, Operation;
        internal readonly uint? NativeCode;
        internal Failure(string state, string code, string message, string operation, uint? nativeCode) : base(message)
        { State = state; Code = code; Operation = operation; NativeCode = nativeCode; }
    }

    private static int Main(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        string command = args.Length == 1 ? args[0] : "";
        try
        {
            if (command != "status" && command != "prepare" && command != "sign")
                throw new Failure("invalid_request", "INVALID_COMMAND", "Only status, prepare and sign are supported; no additional arguments are accepted.", "input", null);
            if (Environment.OSVersion.Platform != PlatformID.Win32NT || !Environment.Is64BitProcess)
                throw new Failure("unsupported", "WINDOWS_X64_REQUIRED", "This helper requires Windows x64.", "platform", null);
            byte[] challenge = command == "sign" ? ReadChallenge() : null;
            ProbeTpm();
            IntPtr provider = IntPtr.Zero, key = IntPtr.Zero;
            try
            {
                Check(NCryptOpenStorageProvider(out provider, Provider, 0), "provider.open");
                uint implementation = GetUInt(provider, "Impl Type");
                if ((implementation & 1) == 0 || (implementation & 2) != 0)
                    throw new Failure("unsupported", "HARDWARE_PROVIDER_REQUIRED", "The platform provider did not report hardware-only key protection.", "provider.verify", null);
                if (command == "prepare") PrepareDirectory();
                uint opened = NCryptOpenKey(provider, out key, KeyName, 0, Machine | Silent);
                bool created = false;
                if (IsMissing(opened))
                {
                    if (command == "status") return Write(Status("not_prepared", false, implementation, null, false));
                    if (command == "sign") throw new Failure("not_prepared", "KEY_NOT_PREPARED", "The project device key has not been prepared.", "key.open", opened);
                    uint creation = NCryptCreatePersistedKey(provider, out key, "ECDSA_P256", KeyName, 0, Machine);
                    if (creation == 0x8009000F) Check(NCryptOpenKey(provider, out key, KeyName, 0, Machine | Silent), "key.reopen");
                    else
                    {
                        Check(creation, "key.create");
                        SetUInt(key, "Export Policy", 0);
                        SetUInt(key, "Key Usage", SignUsage);
                        // Complete the key with its provider's default permissions.
                        // The common preparation path below persists and verifies ACLs.
                        Check(NCryptFinalizeKey(key, Silent), "key.finalize");
                        created = true;
                    }
                }
                else Check(opened, "key.open");
                ValidateKey(key);
                byte[] spki = ExportSpki(key);
                if (command == "prepare")
                {
                    spki = PreparePersistentKeyAcl(spki,
                        delegate { return GetKeySecurityDescriptor(key); },
                        delegate(byte[] descriptor, uint flags) { Check(NCryptSetProperty(key, "Security Descr", descriptor, descriptor.Length, flags), "key.permissions.persist"); },
                        delegate {
                            IntPtr previous = key; key = IntPtr.Zero;
                            Check(NCryptFreeObject(previous), "key.permissions.close");
                            Check(NCryptOpenKey(provider, out key, KeyName, 0, Machine | Silent), "key.permissions.reopen");
                            ValidateKey(key);
                        },
                        delegate { return ExportSpki(key); });
                }
                else if (!InspectAcl(GetKeySecurityDescriptor(key), false).Complete)
                    throw new Failure("needs_admin", "KEY_PERMISSIONS_REQUIRED", "The fixed project key requires permission preparation; it was not changed.", "key.permissions.read", null);
                Dictionary<string, object> output = Status("ready", true, implementation, spki, created);
                if (command == "sign")
                {
                    byte[] hash;
                    using (SHA256 sha = SHA256.Create()) hash = sha.ComputeHash(challenge);
                    int length;
                    Check(NCryptSignHash(key, IntPtr.Zero, hash, hash.Length, null, 0, out length, Silent), "key.sign.size");
                    if (length != 64) throw new Failure("error", "INVALID_SIGNATURE_SIZE", "The provider returned an unexpected P-256 signature size.", "key.sign", null);
                    byte[] signature = new byte[length];
                    Check(NCryptSignHash(key, IntPtr.Zero, hash, hash.Length, signature, signature.Length, out length, Silent), "key.sign");
                    if (length != 64) throw new Failure("error", "INVALID_SIGNATURE_SIZE", "The provider returned an unexpected P-256 signature size.", "key.sign", null);
                    Check(NCryptVerifySignature(key, IntPtr.Zero, hash, hash.Length, signature, signature.Length, Silent), "key.verify");
                    output["signature"] = Base64Url(signature);
                    output["signatureFormat"] = "ieee-p1363";
                    output["hashAlgorithm"] = "SHA-256";
                    Array.Clear(challenge, 0, challenge.Length);
                    Array.Clear(hash, 0, hash.Length);
                }
                return Write(output);
            }
            finally { if (key != IntPtr.Zero) NCryptFreeObject(key); if (provider != IntPtr.Zero) NCryptFreeObject(provider); }
        }
        catch (Failure error)
        {
            Dictionary<string, object> output = Basic(false, error.State);
            output["code"] = error.Code; output["message"] = error.Message; output["operation"] = error.Operation;
            if (error.NativeCode.HasValue) output["nativeCode"] = "0x" + error.NativeCode.Value.ToString("X8");
            return Write(output);
        }
        catch (UnauthorizedAccessException) { return Write(Error("needs_admin", "ACCESS_DENIED", "Preparing or accessing this project's machine resources requires an administrator. No elevation was attempted.")); }
        catch (System.Security.SecurityException) { return Write(Error("needs_admin", "ACCESS_DENIED", "Windows denied access to this project's machine resources. No elevation was attempted.")); }
        catch (DllNotFoundException) { return Write(Error("unsupported", "WINDOWS_API_UNAVAILABLE", "The required Windows TPM or CNG API is unavailable.")); }
        catch (EntryPointNotFoundException) { return Write(Error("unsupported", "WINDOWS_API_UNAVAILABLE", "The required Windows TPM or CNG API is unavailable.")); }
        catch (Exception) { return Write(Error("error", "HELPER_FAILED", "The device helper could not complete the operation; no software key fallback was used.")); }
    }

    private static Dictionary<string, object> Basic(bool ok, string state)
    {
        return new Dictionary<string, object> {
            { "version", 1 }, { "ok", ok }, { "state", state }, { "testMode", TestMode },
            { "tpm", new Dictionary<string, object> { { "present", device.tpmVersion != 0 }, { "version", device.tpmVersion == 2 ? "2.0" : device.tpmVersion == 1 ? "1.2" : "unknown" } } },
            { "storage", StorageStatus() }
        };
    }
    private static Dictionary<string, object> Error(string state, string code, string message)
    { Dictionary<string, object> result = Basic(false, state); result["code"] = code; result["message"] = message; return result; }
    private static Dictionary<string, object> Status(string state, bool prepared, uint implementation, byte[] spki, bool created)
    {
        Dictionary<string, object> result = Basic(true, state);
        result["key"] = new Dictionary<string, object> { { "prepared", prepared }, { "provider", Provider }, { "machineKey", true }, { "hardwareBacked", true }, { "exportable", false }, { "algorithm", "ECDSA_P256" }, { "created", created }, { "implementationFlags", implementation } };
        if (spki != null)
        {
            result["publicKeySpki"] = Base64Url(spki);
            using (SHA256 sha = SHA256.Create()) result["deviceId"] = BitConverter.ToString(sha.ComputeHash(spki)).Replace("-", "").ToLowerInvariant();
        }
        return result;
    }
    private static int Write(Dictionary<string, object> result)
    {
        Console.WriteLine(new JavaScriptSerializer().Serialize(result));
        return (bool)result["ok"] ? 0 : ((string)result["state"] == "needs_admin" ? 20 : 1);
    }
    private static void ProbeTpm()
    {
        device = new TpmInfo { structVersion = 2 };
        uint status = Tbsi_GetDeviceInfo((uint)Marshal.SizeOf(typeof(TpmInfo)), ref device);
        if (status == 0x8028400F) { device.tpmVersion = 0; throw new Failure("no_tpm", "TPM_NOT_FOUND", "Windows did not find a compatible TPM. No software fallback is supported.", "tpm.probe", status); }
        Check(status, "tpm.probe");
        if (device.tpmVersion != 2) throw new Failure("tpm_not_2", "TPM_2_REQUIRED", "A TPM 2.0 device is required.", "tpm.probe", null);
    }
    private static bool IsMissing(uint status) { return status == 0x80090016 || status == 0x80090011; }
    private static void Check(uint status, string operation)
    {
        if (status == 0) return;
        bool denied = status == 5 || status == 0x80070005 || status == 0x80090010 || status == 0x80284012;
        if (denied) throw new Failure("needs_admin", "ACCESS_DENIED", "Windows denied access to this project's machine resources. An administrator may need to prepare them; no elevation was attempted.", operation, status);
        if (status == 0x80090022) throw new Failure("tpm_not_ready", "INTERACTION_REQUIRED", "Windows requires interaction before the device key can be used. No prompt or fallback was invoked.", operation, status);
        if (status == 0x80090029 || status == 0x80090008) throw new Failure("unsupported", "TPM_OPERATION_UNSUPPORTED", "The platform provider does not support the required TPM P-256 operation.", operation, status);
        throw new Failure("error", "TPM_OPERATION_FAILED", "Windows could not complete the required TPM operation. No software fallback was used.", operation, status);
    }
    private static uint GetUInt(IntPtr handle, string property)
    {
        byte[] data = new byte[4]; int count;
        Check(NCryptGetProperty(handle, property, data, data.Length, out count, Silent), "property.read." + property);
        if (count != 4) throw new Failure("error", "INVALID_KEY_PROPERTY", "Windows returned an invalid key property.", "property.read", null);
        return BitConverter.ToUInt32(data, 0);
    }
    private static void SetUInt(IntPtr handle, string property, uint value)
    { byte[] data = BitConverter.GetBytes(value); Check(NCryptSetProperty(handle, property, data, data.Length, 0), "property.write." + property); }
    private static void ValidateKey(IntPtr key)
    {
        if (GetUInt(key, "Export Policy") != 0 || (GetUInt(key, "Key Type") & Machine) == 0 || GetUInt(key, "Length") != 256 || GetUInt(key, "Key Usage") != SignUsage)
            throw new Failure("error", "KEY_POLICY_MISMATCH", "The existing project key does not meet machine-level, non-exportable P-256 signing requirements. It was not changed or replaced.", "key.policy", null);
    }
    private static byte[] ExportSpki(IntPtr key)
    {
        byte[] blob = new byte[72]; int count;
        Check(NCryptExportKey(key, IntPtr.Zero, "ECCPUBLICBLOB", IntPtr.Zero, blob, blob.Length, out count, Silent), "key.public");
        if (count != 72 || BitConverter.ToUInt32(blob, 0) != 0x31534345 || BitConverter.ToUInt32(blob, 4) != 32)
            throw new Failure("error", "INVALID_PUBLIC_KEY", "The project key is not an ECDSA P-256 public key.", "key.public", null);
        // DER SubjectPublicKeyInfo: id-ecPublicKey, prime256v1, uncompressed point.
        byte[] prefix = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04 };
        byte[] spki = new byte[91]; Buffer.BlockCopy(prefix, 0, spki, 0, prefix.Length); Buffer.BlockCopy(blob, 8, spki, prefix.Length, 64); return spki;
    }
    private static byte[] ReadChallenge()
    {
        if (!Console.IsInputRedirected) throw new Failure("invalid_request", "STDIN_REQUIRED", "Provide one canonical base64url challenge through standard input.", "input", null);
        StringBuilder input = new StringBuilder();
        int character;
        while ((character = Console.In.Read()) != -1)
        {
            if (input.Length >= MaximumEncodedCharacters + 2) throw new Failure("invalid_request", "CHALLENGE_TOO_LARGE", "The challenge exceeds the 16 KiB limit.", "input", null);
            input.Append((char)character);
        }
        string encoded = input.ToString();
        if (encoded.EndsWith("\r\n", StringComparison.Ordinal)) encoded = encoded.Substring(0, encoded.Length - 2);
        else if (encoded.EndsWith("\n", StringComparison.Ordinal)) encoded = encoded.Substring(0, encoded.Length - 1);
        if (encoded.Length == 0 || encoded.Length > MaximumEncodedCharacters || !Regex.IsMatch(encoded, "\\A[A-Za-z0-9_-]+\\z") || encoded.Length % 4 == 1)
            throw new Failure("invalid_request", "INVALID_CHALLENGE", "The challenge must use unpadded canonical base64url without whitespace.", "input", null);
        byte[] data = Convert.FromBase64String(encoded.Replace('-', '+').Replace('_', '/') + new string('=', (4 - encoded.Length % 4) % 4));
        if (data.Length == 0 || data.Length > MaximumChallengeBytes || Base64Url(data) != encoded)
            throw new Failure("invalid_request", "INVALID_CHALLENGE", "The challenge must use unpadded canonical base64url without whitespace.", "input", null);
        return data;
    }
    private static string Base64Url(byte[] value) { return Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_'); }
    private static bool HasReparsePoint(string path)
    {
        for (DirectoryInfo directory = new DirectoryInfo(path); directory != null; directory = directory.Parent)
            if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0) return true;
        return false;
    }
    private static byte[] GetKeySecurityDescriptor(IntPtr key)
    {
        int count;
        Check(NCryptGetProperty(key, "Security Descr", null, 0, out count, DaclInformation | OwnerInformation | Silent), "key.permissions.size");
        if (count < 20 || count > 65536) throw new Failure("error", "KEY_ACL_INVALID", "Windows returned an invalid project key security descriptor.", "key.permissions.read", null);
        byte[] descriptor = new byte[count];
        Check(NCryptGetProperty(key, "Security Descr", descriptor, descriptor.Length, out count, DaclInformation | OwnerInformation | Silent), "key.permissions.read");
        if (count < 20 || count > descriptor.Length) throw new Failure("error", "KEY_ACL_INVALID", "Windows returned an invalid project key security descriptor.", "key.permissions.read", null);
        if (count != descriptor.Length) Array.Resize(ref descriptor, count);
        return descriptor;
    }

    // Pure policy inspection and preparation state transitions are separated from
    // OS calls. Tests supply in-memory descriptors and delegates, never TPM keys.
    internal sealed class AclPolicy
    {
        internal RawSecurityDescriptor Descriptor;
        internal bool System, Administrators, Users;
        internal bool Complete { get { return System && Administrators && Users; } }
    }
    private static Failure AclFailure(bool directory, string detail)
    {
        return new Failure("error", directory ? "STORAGE_ACL_POLICY_CONFLICT" : "KEY_ACL_POLICY_CONFLICT",
            "The project " + (directory ? "directory" : "key") + " permissions " + detail + "; existing rules were not overridden.",
            directory ? "storage.permissions" : "key.permissions", null);
    }
    private static uint NormalizeAccess(uint mask, bool directory)
    {
        uint normalized = mask & ~(GenericAll | GenericRead | GenericWrite);
        if ((mask & GenericAll) != 0) normalized |= directory ? (uint)FileSystemRights.FullControl : KeyFull;
        if ((mask & GenericRead) != 0) normalized |= directory ? (uint)(FileSystemRights.Read | FileSystemRights.Synchronize) : KeyRead;
        if ((mask & GenericWrite) != 0) normalized |= directory ? (uint)(FileSystemRights.Write | FileSystemRights.ReadPermissions | FileSystemRights.Synchronize) : KeyWrite;
        if (directory && (mask & 0x20000000) != 0) { normalized &= ~0x20000000u; normalized |= (uint)(FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize); }
        return normalized;
    }
    internal static AclPolicy InspectAcl(byte[] bytes, bool directory)
    {
        RawSecurityDescriptor descriptor;
        try { descriptor = new RawSecurityDescriptor(bytes, 0); }
        catch (ArgumentException) { throw AclFailure(directory, "have an invalid security descriptor"); }
        if ((descriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0 || descriptor.DiscretionaryAcl == null || descriptor.DiscretionaryAcl.Count == 0)
            throw AclFailure(directory, "have no usable DACL");
        uint[] self = new uint[3], files = new uint[3], folders = new uint[3];
        string owner = descriptor.Owner == null ? null : descriptor.Owner.Value;
        foreach (GenericAce entry in descriptor.DiscretionaryAcl)
        {
            CommonAce ace = entry as CommonAce;
            if (ace == null || ace.IsCallback || (ace.AceQualifier != AceQualifier.AccessAllowed && ace.AceQualifier != AceQualifier.AccessDenied))
                throw AclFailure(directory, "contain an unsupported access rule");
            // Even an inherit-only deny may be a deliberate administrator policy.
            if (ace.AceQualifier == AceQualifier.AccessDenied) throw AclFailure(directory, "contain a denial rule");
            string sid = ace.SecurityIdentifier.Value;
            uint mask = NormalizeAccess(unchecked((uint)ace.AccessMask), directory);
            bool inheritOnly = (ace.AceFlags & AceFlags.InheritOnly) != 0;
            bool trusted = sid == SystemSid || sid == AdministratorsSid ||
                (sid == owner && sid != UsersSid && sid != "S-1-1-0" && sid != "S-1-5-11");
            // CREATOR OWNER is a normal inherited directory rule, not a grant to
            // every user on the directory itself. Preserve it without counting it.
            if (directory && sid == "S-1-3-0" && inheritOnly) trusted = true;
            // Observed platform-provider machine-key template: an administrator-
            // owned key retains (A;;FA;;;CO). CREATOR OWNER is a placeholder,
            // not the Users group. Preserve exactly this template without
            // counting it as a usable grant or accepting other principals,
            // masks, inheritance flags, or untrusted owners.
            if (!directory && sid == "S-1-3-0" && ace.AceFlags == AceFlags.None &&
                unchecked((uint)ace.AccessMask) == 0x001F01FFu &&
                (owner == SystemSid || owner == AdministratorsSid)) trusted = true;
            uint ordinary = directory ? (uint)(FileSystemRights.Modify | FileSystemRights.Synchronize) : KeyRead | (uint)CryptoKeyRights.Synchronize;
            if (!trusted && (mask & ~ordinary) != 0) throw AclFailure(directory, "grant management or write access outside the project policy");
            int index = sid == SystemSid ? 0 : sid == AdministratorsSid ? 1 : sid == UsersSid ? 2 : -1;
            if (index < 0) continue;
            if (!inheritOnly) self[index] |= mask;
            if (directory && (ace.AceFlags & AceFlags.NoPropagateInherit) == 0)
            {
                if ((ace.AceFlags & AceFlags.ObjectInherit) != 0) files[index] |= mask;
                if ((ace.AceFlags & AceFlags.ContainerInherit) != 0) folders[index] |= mask;
            }
        }
        bool[] complete = new bool[3];
        for (int index = 0; index < 3; index++)
        {
            uint required = directory ? (uint)(index == 2 ? FileSystemRights.Modify : FileSystemRights.FullControl) : index == 2 ? KeyRead : KeyFull;
            complete[index] = (self[index] & required) == required && (!directory || ((files[index] & required) == required && (folders[index] & required) == required));
        }
        return new AclPolicy { Descriptor = descriptor, System = complete[0], Administrators = complete[1], Users = complete[2] };
    }
    private static byte[] SupplementAcl(AclPolicy policy, bool directory)
    {
        RawAcl acl = policy.Descriptor.DiscretionaryAcl;
        string[] sids = { SystemSid, AdministratorsSid, UsersSid };
        bool[] complete = { policy.System, policy.Administrators, policy.Users };
        for (int index = 0; index < sids.Length; index++)
        {
            if (complete[index]) continue;
            uint mask = directory ? (uint)(index == 2 ? FileSystemRights.Modify | FileSystemRights.Synchronize : FileSystemRights.FullControl) : index == 2 ? GenericRead : GenericAll;
            AceFlags flags = directory ? AceFlags.ContainerInherit | AceFlags.ObjectInherit : AceFlags.None;
            int insertion = 0;
            while (insertion < acl.Count && (acl[insertion].AceFlags & AceFlags.Inherited) == 0) insertion++;
            acl.InsertAce(insertion, new CommonAce(flags, AceQualifier.AccessAllowed, unchecked((int)mask), new SecurityIdentifier(sids[index]), false, null));
        }
        byte[] result = new byte[policy.Descriptor.BinaryLength];
        policy.Descriptor.GetBinaryForm(result, 0);
        return result;
    }
    internal static byte[] PreparePersistentKeyAcl(byte[] expectedSpki, Func<byte[]> readDescriptor, Action<byte[], uint> persistDescriptor, Action reopenAndValidate, Func<byte[]> readSpki)
    {
        AclPolicy policy = InspectAcl(readDescriptor(), false);
        if (!policy.Complete) persistDescriptor(SupplementAcl(policy, false), DaclInformation | PersistProperty);
        // A successful setter is insufficient: close/reopen the exact fixed key,
        // then independently check its stored permissions and unchanged identity.
        reopenAndValidate();
        if (!InspectAcl(readDescriptor(), false).Complete)
            throw new Failure("error", "KEY_PERMISSIONS_NOT_PERSISTED", "The project key permissions did not survive reopening; the key was retained.", "key.permissions.verify", null);
        byte[] actual = readSpki();
        bool same = expectedSpki != null && actual != null && expectedSpki.Length == actual.Length;
        if (same) for (int index = 0; index < actual.Length; index++) if (actual[index] != expectedSpki[index]) { same = false; break; }
        if (!same) throw new Failure("error", "KEY_IDENTITY_CHANGED", "The project public key changed while checking permissions. No replacement was requested.", "key.permissions.identity", null);
        return actual;
    }
    internal static bool PrepareDirectoryAcl(Func<byte[]> readDescriptor, Action<byte[]> writeDescriptor)
    {
        AclPolicy policy = InspectAcl(readDescriptor(), true);
        if (policy.Complete) return false;
        writeDescriptor(SupplementAcl(policy, true));
        if (!InspectAcl(readDescriptor(), true).Complete)
            throw new Failure("error", "STORAGE_PERMISSIONS_NOT_PERSISTED", "The project directory permissions were not confirmed after saving.", "storage.permissions.verify", null);
        return true;
    }
    private static Dictionary<string, object> StorageStatus()
    {
        // Existence is observable without writing a probe file. Writability remains
        // the caller's responsibility when atomically saving the signed license.
        bool exists = Directory.Exists(StoragePath), prepared = false;
        try
        {
            if (exists && !HasReparsePoint(StoragePath))
            {
                prepared = InspectAcl(Directory.GetAccessControl(StoragePath, AccessControlSections.Access | AccessControlSections.Owner).GetSecurityDescriptorBinaryForm(), true).Complete;
            }
        }
        catch (Failure) { }
        catch (UnauthorizedAccessException) { }
        catch (System.Security.SecurityException) { }
        catch (IOException) { }
        return new Dictionary<string, object> { { "path", StoragePath }, { "exists", exists }, { "prepared", prepared } };
    }
    private static void PrepareDirectory()
    {
        if (HasReparsePoint(StoragePath)) throw new Failure("error", "UNSAFE_STORAGE_PATH", "The fixed project licensing directory must not contain a reparse point.", "storage.prepare", null);
        if (!Directory.Exists(StoragePath)) Directory.CreateDirectory(StoragePath);
        if (HasReparsePoint(StoragePath)) throw new Failure("error", "UNSAFE_STORAGE_PATH", "The fixed project licensing directory must not contain a reparse point.", "storage.prepare", null);
        PrepareDirectoryAcl(
            delegate { return Directory.GetAccessControl(StoragePath, AccessControlSections.Access | AccessControlSections.Owner).GetSecurityDescriptorBinaryForm(); },
            delegate(byte[] descriptor) {
                if (HasReparsePoint(StoragePath)) throw new Failure("error", "UNSAFE_STORAGE_PATH", "The fixed project licensing directory must not contain a reparse point.", "storage.prepare", null);
                DirectorySecurity acl = new DirectorySecurity();
                acl.SetSecurityDescriptorBinaryForm(descriptor, AccessControlSections.Access);
                Directory.SetAccessControl(StoragePath, acl);
            });
    }
}
