using System;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Web.Script.Serialization;

// Compiled with /main:AclPolicyTests. LianpuTpm.Main is never called.
// All descriptors and CNG-boundary delegates are in memory. No filesystem ACL,
// persisted key, TPM, helper command, or elevation operation is used here.
internal static class AclPolicyTests
{
    private const string KeyReady = "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)";
    private const string KeyMissingUsers = "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)";
    private const string DirectoryReady = "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)";
    private static readonly List<object> Results = new List<object>();
    private static byte[] Descriptor(string sddl) { RawSecurityDescriptor descriptor = new RawSecurityDescriptor(sddl); byte[] bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0); return bytes; }
    private static void Equal<T>(T actual, T expected) { if (!Object.Equals(actual, expected)) throw new Exception("Expected " + expected + ", received " + actual); }
    private static void Fails(string code, Action action)
    {
        try { action(); }
        catch (LianpuTpm.Failure failure) { Equal(failure.Code, code); return; }
        throw new Exception("Expected failure " + code);
    }
    private static void Case(string name, Action test)
    {
        try { test(); Results.Add(new { name = name, passed = true }); }
        catch (Exception error) { Results.Add(new { name = name, passed = false, error = error.Message }); Environment.ExitCode = 1; }
    }
    private static void Main()
    {
        Case("Compliant directory needs no ACL write", delegate {
            int reads = 0, writes = 0;
            Equal(LianpuTpm.PrepareDirectoryAcl(delegate { reads++; return Descriptor(DirectoryReady); }, delegate { writes++; }), false);
            Equal(reads, 1); Equal(writes, 0);
        });
        Case("Inherit-only Users permission is not treated as access to the directory", delegate {
            byte[] stored = Descriptor("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;0x1301bf;;;BU)");
            Equal(LianpuTpm.InspectAcl(stored, true).Complete, false);
            int writes = 0;
            Equal(LianpuTpm.PrepareDirectoryAcl(delegate { return stored; }, delegate(byte[] value) { stored = value; writes++; }), true);
            Equal(writes, 1); Equal(LianpuTpm.InspectAcl(stored, true).Complete, true);
            Equal(new RawSecurityDescriptor(stored, 0).DiscretionaryAcl.Count, 4);
        });
        Case("Directory administrator denial is preserved without writing", delegate {
            int writes = 0;
            Fails("STORAGE_ACL_POLICY_CONFLICT", delegate {
                LianpuTpm.PrepareDirectoryAcl(delegate { return Descriptor("O:SYD:P(D;OICI;FA;;;BU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"); }, delegate { writes++; });
            });
            Equal(writes, 0);
        });
        Case("Directory ACL must be confirmed after its write", delegate {
            byte[] unchanged = Descriptor("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"); int writes = 0;
            Fails("STORAGE_PERMISSIONS_NOT_PERSISTED", delegate { LianpuTpm.PrepareDirectoryAcl(delegate { return unchanged; }, delegate { writes++; }); });
            Equal(writes, 1);
        });
        Case("Compliant key is not written but is reopened and identity checked", delegate {
            List<string> calls = new List<string>(); byte[] spki = { 1, 2, 3 };
            LianpuTpm.PreparePersistentKeyAcl(spki,
                delegate { calls.Add("read"); return Descriptor(KeyReady); }, delegate { calls.Add("write"); },
                delegate { calls.Add("reopen"); }, delegate { calls.Add("public"); return new byte[] { 1, 2, 3 }; });
            Equal(String.Join(",", calls), "read,reopen,read,public");
        });
        Case("Missing Users grant is supplemented with explicit persistence flags", delegate {
            byte[] durable = Descriptor(KeyMissingUsers), pending = null, spki = { 1, 2, 3 }; int writes = 0; uint flagsSeen = 0;
            LianpuTpm.PreparePersistentKeyAcl(spki, delegate { return durable; },
                delegate(byte[] value, uint flags) { writes++; flagsSeen = flags; pending = value; },
                delegate { if (flagsSeen == 0x80000004) durable = pending; }, delegate { return spki; });
            Equal(flagsSeen, 0x80000004u); Equal(writes, 1); Equal(LianpuTpm.InspectAcl(durable, false).Complete, true);
        });
        Case("Successful setter with failed persistent readback is rejected", delegate {
            byte[] unchanged = Descriptor(KeyMissingUsers); int writes = 0, opens = 0, identities = 0;
            Fails("KEY_PERMISSIONS_NOT_PERSISTED", delegate {
                LianpuTpm.PreparePersistentKeyAcl(new byte[] { 1 }, delegate { return unchanged; }, delegate { writes++; }, delegate { opens++; }, delegate { identities++; return new byte[] { 1 }; });
            });
            Equal(writes, 1); Equal(opens, 1); Equal(identities, 0);
        });
        Case("Key identity change after reopen is rejected", delegate {
            int writes = 0;
            Fails("KEY_IDENTITY_CHANGED", delegate {
                LianpuTpm.PreparePersistentKeyAcl(new byte[] { 1 }, delegate { return Descriptor(KeyReady); }, delegate { writes++; }, delegate { }, delegate { return new byte[] { 2 }; });
            });
            Equal(writes, 0);
        });
        Case("Existing key denial cannot be overridden by preparation", delegate {
            int writes = 0, opens = 0;
            Fails("KEY_ACL_POLICY_CONFLICT", delegate {
                LianpuTpm.PreparePersistentKeyAcl(new byte[] { 1 }, delegate { return Descriptor("O:SYD:P(D;;GR;;;BU)(A;;GA;;;SY)(A;;GA;;;BA)"); }, delegate { writes++; }, delegate { opens++; }, delegate { return new byte[] { 1 }; });
            });
            Equal(writes, 0); Equal(opens, 0);
        });
        Case("Users management rights are a policy conflict, not silently narrowed", delegate {
            int writes = 0;
            Fails("KEY_ACL_POLICY_CONFLICT", delegate {
                LianpuTpm.PreparePersistentKeyAcl(new byte[] { 1 }, delegate { return Descriptor("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;BU)"); }, delegate { writes++; }, delegate { }, delegate { return new byte[] { 1 }; });
            });
            Equal(writes, 0);
        });
        Case("Default creating-owner permissions survive supplementation", delegate {
            const string owner = "S-1-5-21-111-222-333-1001";
            byte[] stored = Descriptor("O:" + owner + "D:P(A;;GA;;;" + owner + ")(A;;GA;;;SY)");
            LianpuTpm.PreparePersistentKeyAcl(new byte[] { 1 }, delegate { return stored; }, delegate(byte[] value, uint flags) { stored = value; }, delegate { }, delegate { return new byte[] { 1 }; });
            RawSecurityDescriptor descriptor = new RawSecurityDescriptor(stored, 0);
            Equal(descriptor.Owner.Value, owner); Equal(descriptor.DiscretionaryAcl.Count, 4);
            Equal(((CommonAce)descriptor.DiscretionaryAcl[0]).SecurityIdentifier.Value, owner);
            Equal(((CommonAce)descriptor.DiscretionaryAcl[0]).AccessMask, 0x10000000);
            Equal(LianpuTpm.InspectAcl(stored, false).Complete, true);
        });
        Case("Provider-normalized concrete read masks remain acceptable", delegate {
            Equal(LianpuTpm.InspectAcl(Descriptor("O:SYD:P(A;;0x1f01ff;;;SY)(A;;GA;;;BA)(A;;0x120089;;;BU)"), false).Complete, true);
        });
        Case("Observed platform-provider CREATOR OWNER template is preserved without counting as Users", delegate {
            byte[] stored = Descriptor("O:BAD:P(A;;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)");
            Equal(LianpuTpm.InspectAcl(stored, false).Complete, false);
            int writes = 0; byte[] spki = { 4, 5, 6 };
            LianpuTpm.PreparePersistentKeyAcl(spki, delegate { return stored; }, delegate(byte[] value, uint flags) { writes++; stored = value; }, delegate { }, delegate { return spki; });
            var descriptor = new RawSecurityDescriptor(stored, 0);
            Equal(writes, 1); Equal(descriptor.Owner.Value, "S-1-5-32-544");
            Equal(descriptor.DiscretionaryAcl.Count, 4);
            var creator = (CommonAce)descriptor.DiscretionaryAcl[0];
            Equal(creator.SecurityIdentifier.Value, "S-1-3-0"); Equal(creator.AccessMask, 0x001F01FF); Equal(creator.AceFlags, AceFlags.None);
            var users = (CommonAce)descriptor.DiscretionaryAcl[3];
            Equal(users.SecurityIdentifier.Value, "S-1-5-32-545"); Equal(unchecked((uint)users.AccessMask), 0x80000000u);
            Equal(LianpuTpm.InspectAcl(stored, false).Complete, true);
        });
        Case("CREATOR OWNER exception requires a trusted system or administrator owner", delegate {
            Fails("KEY_ACL_POLICY_CONFLICT", delegate { LianpuTpm.InspectAcl(Descriptor("O:BUD:P(A;;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)"), false); });
            Fails("KEY_ACL_POLICY_CONFLICT", delegate { LianpuTpm.InspectAcl(Descriptor("D:P(A;;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)"), false); });
        });
        Case("CREATOR OWNER exception cannot admit other masks flags groups or denials", delegate {
            string[] rules = { "(A;OI;FA;;;CO)", "(A;;0x101f01ff;;;CO)", "(A;;FA;;;CG)", "(D;;FA;;;CO)" };
            foreach (string rule in rules) Fails("KEY_ACL_POLICY_CONFLICT", delegate { LianpuTpm.InspectAcl(Descriptor("O:BAD:P" + rule + "(A;;FA;;;SY)(A;;FA;;;BA)"), false); });
        });
        Case("Default template never legitimizes a separate broad Users grant", delegate {
            Fails("KEY_ACL_POLICY_CONFLICT", delegate { LianpuTpm.InspectAcl(Descriptor("O:BAD:P(A;;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)"), false); });
        });
        Case("Absent DACL is not accepted as prepared", delegate {
            Fails("KEY_ACL_POLICY_CONFLICT", delegate { LianpuTpm.InspectAcl(Descriptor("O:SY"), false); });
        });
        Console.WriteLine(new JavaScriptSerializer().Serialize(new { pureAclOnly = true, tests = Results.Count, results = Results }));
    }
}
