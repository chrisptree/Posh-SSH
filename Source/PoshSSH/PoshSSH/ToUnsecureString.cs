

using System;
using System.Runtime.InteropServices;
using System.Security;

namespace SSH
{
    public static class StringExtensions
    {
        /// <summary>
        /// Converts a <see cref="SecureString"/> to an unsecure string.
        /// </summary>
        /// <param name="secureString">The <see cref="SecureString"/> to operate on</param>
        /// <returns>An unsecure string</returns>
        public static string ToUnsecureString(this SecureString secureString)
        {
            if (secureString == null) return null;

            var unmanagedString = IntPtr.Zero;

            try
            {
                unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                return Marshal.PtrToStringUni(unmanagedString);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }
    }
}