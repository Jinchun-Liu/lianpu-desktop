using System;
using System.Collections.Generic;
using System.IO;
using System.Web.Script.Serialization;

// Selected with /main:SigningPolicyTests. LianpuTpm.Main is never called.
internal static class SigningPolicyTests
{
    private static int Main(string[] args)
    {
        JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = 1048576 };
        object[] vectors = (object[])json.DeserializeObject(File.ReadAllText(args[0]));
        List<object> results = new List<object>(); bool passed = true;
        foreach (object entry in vectors)
        {
            Dictionary<string, object> vector = (Dictionary<string, object>)entry;
            string actual;
            try { actual = LianpuTpm.ValidateSigningChallenge(Convert.FromBase64String((string)vector["base64"])); }
            catch (LianpuTpm.Failure failure) { actual = failure.Code; }
            bool matches = actual == (string)vector["nativeExpected"]; passed &= matches;
            results.Add(new { name = vector["name"], passed = matches, actual = actual });
        }
        Console.WriteLine(json.Serialize(new { pureSigningPolicyOnly = true, hardwareInvoked = false, passed = passed, tests = results.Count, results = results }));
        return passed ? 0 : 1;
    }
}
