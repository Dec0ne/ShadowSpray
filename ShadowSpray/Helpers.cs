using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ShadowSpray
{
    public static class Helpers
    {

        //Code taken from Rubeus
        public static DirectoryEntry GetLdapSearchRoot(string OUName, string domainController, string domain)
        {
            DirectoryEntry directoryObject = null;
            string ldapPrefix = "";
            string ldapOu = "";

            //If we have a DC then use that instead of the domain name so that this works if user doesn't have
            //name resolution working but specified the IP of a DC
            if (!String.IsNullOrEmpty(domainController))
            {
                ldapPrefix = domainController;
            }
            else if (!String.IsNullOrEmpty(domain)) //If we don't have a DC then use the domain name (if we have one)
            {
                ldapPrefix = domain;
            }

            if (!String.IsNullOrEmpty(OUName))
            {
                ldapOu = OUName.Replace("ldap", "LDAP").Replace("LDAP://", "");
            }
            else if (!String.IsNullOrEmpty(domain))
            {
                ldapOu = String.Format("DC={0}", domain.Replace(".", ",DC="));
            }

            //If no DC, domain, credentials, or OU were specified
            if (String.IsNullOrEmpty(ldapPrefix) && String.IsNullOrEmpty(ldapOu))
            {
                directoryObject = new DirectoryEntry();
            }
            else //If we have a prefix (DC or domain), an OU path, or both
            {
                string bindPath = "";
                if (!String.IsNullOrEmpty(ldapPrefix))
                {
                    bindPath = String.Format("LDAP://{0}", ldapPrefix);
                }
                if (!String.IsNullOrEmpty(ldapOu))
                {
                    if (!String.IsNullOrEmpty(bindPath))
                    {
                        bindPath = String.Format("{0}/{1}", bindPath, ldapOu);
                    }
                    else
                    {
                        bindPath = String.Format("LDAP://{1]", ldapOu);
                    }
                }

                directoryObject = new DirectoryEntry(bindPath);
            }

            if (directoryObject != null)
            {
                directoryObject.AuthenticationType = AuthenticationTypes.Secure | AuthenticationTypes.Sealing | AuthenticationTypes.Signing;
            }

            return directoryObject;
        }

        //Code taken from Rubeus
        public static DirectoryEntry LocateAccount(string username, string domain, string domainController)
        {
            DirectoryEntry directoryObject = null;
            DirectorySearcher userSearcher = null;

            try
            {
                directoryObject = GetLdapSearchRoot("", domainController, domain);
                userSearcher = new DirectorySearcher(directoryObject);
                userSearcher.PageSize = 1;
            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    Console.WriteLine("\r\n[-] Error creating the domain searcher: {0}", ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("\r\n[-] Error creating the domain searcher: {0}", ex.Message);
                }
                return null;
            }

            // check to ensure that the bind worked correctly
            try
            {
                string dirPath = directoryObject.Path;
                if (Options.verbose)
                    Console.WriteLine("[+] Searching for the target account");
            }
            catch (DirectoryServicesCOMException ex)
            {
                Console.WriteLine("\r\n[-] Error validating the domain searcher: {0}", ex.Message);
                return null;
            }

            try
            {
                string userSearchFilter = String.Format("(samAccountName={0})", username);
                userSearcher.Filter = userSearchFilter;
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n[-] Error settings the domain searcher filter: {0}", ex.InnerException.Message);
                return null;
            }

            try
            {
                SearchResult user = userSearcher.FindOne();

                if (user == null)
                {
                    Console.WriteLine("[!] Target user not found");
                }

                string distinguishedName = user.Properties["distinguishedName"][0].ToString();
                if (Options.verbose)
                    Console.WriteLine("[+] Target user found: {0}", distinguishedName);

                return user.GetDirectoryEntry();

            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    Console.WriteLine("\r\n[-] Error executing the domain searcher: {0}", ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("\r\n[-] Error executing the domain searcher: {0}", ex.Message);
                }
                return null;
            }
        }

        public static string RandomPasswordGenerator(int length)
        {
            string alphaCaps = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string alphaLow = "abcdefghijklmnopqrstuvwxyz";
            string numerics = "1234567890";
            string special = "@#$-=/";
            string[] allChars = { alphaLow, alphaCaps, numerics, special };
            StringBuilder res = new StringBuilder();
            Random rnd = new Random();
            int t = 0;
            while (0 < length--)
            {
                res.Append(allChars[t][rnd.Next(allChars[t].Length)]);
                if (t == 3)
                    t = 0;
                else
                    t++;
            }
            return res.ToString();
        }

        internal static IEnumerable<IntPtr> GetPointerArray(IntPtr array)
        {
            if (array != IntPtr.Zero)
            {
                var count = 0;
                var tempPtr = Marshal.ReadIntPtr(array, count * IntPtr.Size);
                while (tempPtr != IntPtr.Zero)
                {
                    yield return tempPtr;
                    count++;
                    tempPtr = Marshal.ReadIntPtr(array, count * IntPtr.Size);
                }
            }
        }

        internal static IntPtr AllocHGlobalIntPtrArray(int size)
        {
            checked
            {
                var intPtrArray = Marshal.AllocHGlobal(IntPtr.Size * size);
                for (var i = 0; i < size; i++)
                {
                    Marshal.WriteIntPtr(intPtrArray, IntPtr.Size * i, IntPtr.Zero);
                }

                return intPtrArray;
            }
        }

        internal static void BerValFree(IntPtr berval)
        {
            if (berval != IntPtr.Zero)
            {
                var b = (Natives.berval)Marshal.PtrToStructure(berval, typeof(Natives.berval));
                Marshal.FreeHGlobal(b.bv_val);
                Marshal.FreeHGlobal(berval);
            }
        }

        internal static void BerValuesFree(IntPtr array)
        {
            foreach (var ptr in GetPointerArray(array))
            {
                BerValFree(ptr);
            }
        }

        internal static void StructureArrayToPtr<T>(IEnumerable<T> array, IntPtr ptr, bool endNull = false)
        {
            var ptrArray = array.Select(structure =>
            {
                var structPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)));
                Marshal.StructureToPtr(structure, structPtr, false);
                return structPtr;
            }).ToList();
            if (endNull)
            {
                ptrArray.Add(IntPtr.Zero);
            }

            Marshal.Copy(ptrArray.ToArray(), 0, ptr, ptrArray.Count);
        }

        internal static void ByteArraysToBerValueArray(byte[][] sourceData, IntPtr ptr)
        {
            for (var i = 0; i < sourceData.Length; i++)
            {
                var berPtr = ByteArrayToBerValue(sourceData[i]);
                Marshal.WriteIntPtr(ptr, i * IntPtr.Size, berPtr);
            }

            Marshal.WriteIntPtr(ptr, sourceData.Length * IntPtr.Size, IntPtr.Zero);
        }

        public static List<byte[]> BerValArrayToByteArrays(IntPtr ptr)
        {
            var result = new List<byte[]>();
            foreach (var tempPtr in GetPointerArray(ptr))
            {
                var bervalue = new Natives.berval();
                Marshal.PtrToStructure(tempPtr, bervalue);
                if (bervalue.bv_len > 0 && bervalue.bv_val != IntPtr.Zero)
                {
                    var byteArray = new byte[bervalue.bv_len];
                    Marshal.Copy(bervalue.bv_val, byteArray, 0, bervalue.bv_len);
                    result.Add(byteArray);
                }
            }

            return result;
        }

        internal static IntPtr ByteArrayToBerValue(byte[] bytes)
        {
            var berPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Natives.berval)));
            var valPtr = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, valPtr, bytes.Length);
            Marshal.StructureToPtr(new Natives.berval
            {
                bv_val = valPtr,
                bv_len = bytes.Length
            }, berPtr, true);
            return berPtr;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

    }
}
