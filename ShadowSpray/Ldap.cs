using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static ShadowSpray.Natives;

namespace ShadowSpray
{

    internal class Ldap
    {

        public static Dictionary<string, List<byte[]>> GetLdapAttributes(IntPtr ld, IntPtr entry, ref IntPtr ber)
        {
            Dictionary<string, List<byte[]>> list = new Dictionary<string, List<byte[]>>();
            for (var attr = ldap_first_attribute(ld, entry, ref ber);
                attr != IntPtr.Zero;
                attr = ldap_next_attribute(ld, entry, ber))
            {
                var vals = ldap_get_values_len(ld, entry, attr);
                if (vals != IntPtr.Zero)
                {
                    var attrName = Marshal.PtrToStringUni(attr);
                    if (attrName != null)
                    {
                        list.Add(
                            attrName,
                            Helpers.BerValArrayToByteArrays(vals)
                        );
                    }
                    ldap_value_free_len(vals);
                }
            }
            return list;
        }

        public static string GetLdapDn(IntPtr ld, IntPtr entry)
        {
            var ptr = ldap_get_dn(ld, entry);
            var dn = Marshal.PtrToStringUni(ptr);
            return dn;
        }

        public static LdapStatus setAttribute(IntPtr ld, string attribute, byte[] value, string dn)
        {
            var modPropPtr = Marshal.StringToHGlobalUni(attribute);
            var modValue = new List<byte[]> {
                value
            };
            var modValuePtr = Marshal.AllocHGlobal(IntPtr.Size * 2);
            Helpers.ByteArraysToBerValueArray(modValue.Select(_ => _ ?? Array.Empty<byte>()).ToArray(), modValuePtr);
            List<LDAPMod> mod = new List<LDAPMod> {
                new LDAPMod {
                    mod_op = (int)LdapModOperation.LDAP_MOD_REPLACE | (int)LdapModOperation.LDAP_MOD_BVALUES,
                    mod_type = modPropPtr,
                    mod_vals_u = new LDAPMod.mod_vals
                    {
                        modv_bvals = modValuePtr
                    },
                    mod_next = IntPtr.Zero
                }
            };
            var ptr = Marshal.AllocHGlobal(IntPtr.Size * 2); // alloc memory for list with last element null
            Helpers.StructureArrayToPtr(mod, ptr, true);

            //int rest = ldap_modify_ext(ld, dn, ptr, IntPtr.Zero, IntPtr.Zero, out int pMessage);
            int rest = ldap_modify_s(ld, dn, ptr);

            mod.ForEach(_ =>
            {
                Helpers.BerValuesFree(_.mod_vals_u.modv_bvals);
                Marshal.FreeHGlobal(_.mod_vals_u.modv_bvals);
                Marshal.FreeHGlobal(_.mod_type);
            });
            Marshal.FreeHGlobal(ptr);

            return (LdapStatus)rest;
        }

        public static LdapStatus clearAttribute(IntPtr ld, string attribute, string dn)
        {
            var modPropPtr = Marshal.StringToHGlobalUni(attribute);
            var modValue = new List<byte[]> { };
            var modValuePtr = Marshal.AllocHGlobal(IntPtr.Size * 2);
            Helpers.ByteArraysToBerValueArray(modValue.Select(_ => _ ?? Array.Empty<byte>()).ToArray(), modValuePtr);
            List<LDAPMod> mod = new List<LDAPMod> {
                new LDAPMod {
                    mod_op = (int)LdapModOperation.LDAP_MOD_REPLACE | (int)LdapModOperation.LDAP_MOD_BVALUES,
                    mod_type = modPropPtr,
                    mod_vals_u = new LDAPMod.mod_vals
                    {
                        modv_bvals = modValuePtr
                    },
                    mod_next = IntPtr.Zero
                }
            };
            var ptr = Marshal.AllocHGlobal(IntPtr.Size * 2); // alloc memory for list with last element null
            Helpers.StructureArrayToPtr(mod, ptr, true);

            //int rest = ldap_modify_ext(ld, dn, ptr, IntPtr.Zero, IntPtr.Zero, out int pMessage);
            int rest = ldap_modify_s(ld, dn, ptr);

            mod.ForEach(_ =>
            {
                Helpers.BerValuesFree(_.mod_vals_u.modv_bvals);
                Marshal.FreeHGlobal(_.mod_vals_u.modv_bvals);
                Marshal.FreeHGlobal(_.mod_type);
            });
            Marshal.FreeHGlobal(ptr);

            return (LdapStatus)rest;
        }

        public static LdapStatus addAttribute(IntPtr ld, string attribute, byte[] value, string dn)
        {
            var modPropPtr = Marshal.StringToHGlobalUni(attribute);
            var modValue = new List<byte[]> {
                value
            };
            var modValuePtr = Marshal.AllocHGlobal(IntPtr.Size * 2);
            Helpers.ByteArraysToBerValueArray(modValue.Select(_ => _ ?? Array.Empty<byte>()).ToArray(), modValuePtr);
            List<LDAPMod> mod = new List<LDAPMod> {
                new LDAPMod {
                    mod_op = (int)LdapModOperation.LDAP_MOD_ADD | (int)LdapModOperation.LDAP_MOD_BVALUES,
                    mod_type = modPropPtr,
                    mod_vals_u = new LDAPMod.mod_vals
                    {
                        modv_bvals = modValuePtr
                    },
                    mod_next = IntPtr.Zero
                }
            };
            var ptr = Marshal.AllocHGlobal(IntPtr.Size * 2); // alloc memory for list with last element null
            Helpers.StructureArrayToPtr(mod, ptr, true);

            //int rest = ldap_modify_ext(ld, dn, ptr, IntPtr.Zero, IntPtr.Zero, out int pMessage);
            int rest = ldap_modify_s(ld, dn, ptr);

            mod.ForEach(_ =>
            {
                Helpers.BerValuesFree(_.mod_vals_u.modv_bvals);
                Marshal.FreeHGlobal(_.mod_vals_u.modv_bvals);
                Marshal.FreeHGlobal(_.mod_type);
            });
            Marshal.FreeHGlobal(ptr);

            return (LdapStatus)rest;
        }

        public static LdapStatus removeAttribute(IntPtr ld, string attribute, byte[] value, string dn)
        {
            var modPropPtr = Marshal.StringToHGlobalUni(attribute);
            var modValue = new List<byte[]> {
                value
            };
            var modValuePtr = Marshal.AllocHGlobal(IntPtr.Size * 2);
            Helpers.ByteArraysToBerValueArray(modValue.Select(_ => _ ?? Array.Empty<byte>()).ToArray(), modValuePtr);
            List<LDAPMod> mod = new List<LDAPMod> {
                new LDAPMod {
                    mod_op = (int)LdapModOperation.LDAP_MOD_DELETE | (int)LdapModOperation.LDAP_MOD_BVALUES,
                    mod_type = modPropPtr,
                    mod_vals_u = new LDAPMod.mod_vals
                    {
                        modv_bvals = modValuePtr
                    },
                    mod_next = IntPtr.Zero
                }
            };
            var ptr = Marshal.AllocHGlobal(IntPtr.Size * 2); // alloc memory for list with last element null
            Helpers.StructureArrayToPtr(mod, ptr, true);

            //int rest = ldap_modify_ext(ld, dn, ptr, IntPtr.Zero, IntPtr.Zero, out int pMessage);
            int rest = ldap_modify_s(ld, dn, ptr);

            mod.ForEach(_ =>
            {
                Helpers.BerValuesFree(_.mod_vals_u.modv_bvals);
                Marshal.FreeHGlobal(_.mod_vals_u.modv_bvals);
                Marshal.FreeHGlobal(_.mod_type);
            });
            Marshal.FreeHGlobal(ptr);

            return (LdapStatus)rest;
        }
    }
}
