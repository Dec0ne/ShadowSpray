
# ShadowSpray
A tool to spray [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.

### Why this tool
In a lot of engagements I see (in [BloodHound](https://github.com/BloodHoundAD/BloodHound)) that the group "Everyone" / "Authenticated Users" / "Domain Users" or some other wide group, which contains almost all the users in the domain, has some GenericWrite/GenericAll DACLs over other objects in the domain.

![example](Images/bloodhound.png)

These rights can be abused to add Shadow Credentials on the target object and obtain it's TGT and NT Hash.

It occurred to me that we can just try and spray shadow credentials over the entire domain and see what's sticks (obviously this approach is better suited to non-stealth engagements, don't use this in a red team where stealth is required). When a Shadow Credentials is successfuly added, we simply do the whole PKINIT + UnPACTheHash dance and voilà - we get NT Hashes. 

Since the process is extremely fast, this can be used at the very start of the engagement, and hopefully you'll have some users and computers owned before you even start.

**Note**: I recycled a lot of code from my [previous tool](https://github.com/Dec0ne/KrbRelayUp) so AV/EDRs might flag this as KrbRelayUp...

### How this tool works
It goes something like this:

0. Login to the domain with the supplied credentials (Or use the current session).
1. Check that the domain functional level is 2016 (Otherwise stop since the Shadow Credentials attack won't work)
2. Gather a list of all the objects in the domain (users and computers) from LDAP.
3. For every object in the list do the following:
   1. Try to add KeyCredential to the object's "msDS-KeyCredentialLink" attribute.
   2. If the above is successful, use PKINIT to request a TGT using the added KeyCredential.
   3. If the above is successful, perform an UnPACTheHash attack to reveal the user/computer NT hash.
   4. If **--RestoreShadowCred** was specified: Remove the added KeyCredential (clean up after yourself...) 
4. If **--Recursive** was specified: Do the same process using each of the user/computer accounts we successfully owned.

ShadowSpray supports CTRL+C so if at any point you wish to stop the execution just hit CTRL+C and ShadowSpray will display the NT Hashes recovered so far before exiting (as shown in the demo below).

## Demo

https://user-images.githubusercontent.com/54464773/194827503-b1eead1a-e09a-41ca-9d9b-0a7a6f0ad6a0.mp4

## Usage
```
 __             __   __        __   __   __
/__` |__|  /\  |  \ /  \ |  | /__` |__) |__)  /\  \ /
.__/ |  | /~~\ |__/ \__/ |/\| .__/ |    |  \ /~~\  |


Usage: ShadowSpray.exe [-d FQDN] [-dc FQDN] [-u USERNAME] [-p PASSWORD] [-r] [-re] [-cp CERT_PASSWORD] [-ssl]

    -r   (--RestoreShadowCred)       Restore "msDS-KeyCredentialLink" attribute after the attack is done. (Optional)
    -re  (--Recursive)               Perform ShadowSpray attack recursivly. (Optional)
    -cp  (--CertificatePassword)     Certificate password. (default = random password)


General Options:
    -u  (--Username)                 Username for initial LDAP authentication. (Optional)
    -p  (--Password)                 Password for initial LDAP authentication. (Optional)
    -d  (--Domain)                   FQDN of domain. (Optional)
    -dc (--DomainController)         FQDN of domain controller. (Optional)
    -ssl                             Use LDAP over SSL. (Optional)
    -y  (--AutoY)                    Don't ask for confirmation to start the ShadowSpray attack. (Optional)
```

## TODO
- [ ] Code refactoring and cleanup!!!
- [ ] Add Verbose output option
- [ ] Add option to save KeyCredentials added / TGT requested / NT Hashes gathered to a file on disk
- [ ] Python version ;)
- [ ] Other suggestions will be welcomed

## Mitigation and Detection
Taken from [Elad Shamir](https://twitter.com/elad_shamir)'s blog post on [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab):
* If PKINIT authentication is not common in the environment or not common for the target account, the “Kerberos authentication ticket (TGT) was requested” event (4768) can indicate anomalous behavior when the Certificate Information attributes are not blank.
* If a SACL is configured to audit Active Directory object modifications for the targeted account, the “Directory service object was modified” event (5136) can indicate anomalous behavior if the subject changing the msDS-KeyCredentialLink is not the Azure AD Connect synchronization account or the ADFS service account, which will typically act as the Key Provisioning Server and legitimately modify this attribute for users.
* A more specific preventive control is adding an Access Control Entry (ACE) to DENY the principal EVERYONE from modifying the attribute msDS-KeyCredentialLink for any account not meant to be enrolled in Key Trust passwordless authentication, and particularly privileged accounts.
 
*  [Detecting UnPACing and shadowed credentials](https://medium.com/falconforce/falconfriday-detecting-unpacing-and-shadowed-credentials-0xff1e-2246934247ce) by Henri Hambartsumyan of [FalconForce](https://twitter.com/falconforceteam)

ShadowSpray specific detections:
* This tool attempts to modify **every** user/computer object in the domain in a very short timeframe, when it fails (most of the time) it generates an **LDAP_INSUFFICIENT_ACCESS** error. It's possible to build detection around that using the same approach of detecting regular password spray.

## Acknowledgements
* [Elad Shamir](https://twitter.com/elad_shamir) for his research on [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) and his awsome tool [Whisker](https://github.com/eladshamir/Whisker).
* [Will Schroeder](https://twitter.com/harmj0y) and everyone who contributed to [Rubeus](https://github.com/GhostPack/Rubeus/) which we all know and love. Basically all the TGT/TGS/UnPACTheHash functionality was taken from there.
* [Cube0x0](https://twitter.com/cube0x0) Some of the code (specifically the modifications of LDAP attributes via WINAPI) was taken from his amazing tool [KrbRelay](https://github.com/cube0x0/KrbRelay).
* [Michael Grafnetter](https://twitter.com/mgrafnetter) for his tool [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) which was used here to help with the Shadow Credentials functionality.
* [Orange-Cyberdefense](https://github.com/Orange-Cyberdefense) for their work on [GOAD](https://github.com/Orange-Cyberdefense/GOAD), the Active Directory research lab I am using which you can see in the demo video and images.
* [Martijn Laarman](https://twitter.com/Mpdreamz) for the nice [progress bar](https://github.com/Mpdreamz/shellprogressbar) used in this tool.
