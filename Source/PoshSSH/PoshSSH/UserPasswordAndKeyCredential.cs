using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace SSH
{
    public class UserPasswordAndKeyCredential : PSObject
    {
        public UserPasswordAndKeyCredential(PSCredential credential, string keyFile, SecureString keyPhrase) : base()
        {
            Credential = credential;
            KeyFile = keyFile;
            KeyPhrase = keyPhrase;
        }

        public UserPasswordAndKeyCredential(PSCredential credential, string[] keyString) : base()
        {
            Credential = credential;
            KeyString = keyString;
        }

        /// <summary>
        /// Credentials for Connection
        /// </summary>
        [ValidateNotNullOrEmpty]
        [Parameter(HelpMessage = "SSH Credentials to use for connecting to a server.")]
        [Credential()]
        public PSCredential Credential { get; set; }

        /// <summary>
        /// SSH Key File
        /// </summary>
        [Parameter(HelpMessage = "OpenSSH format SSH private key file.")]
        public string KeyFile { get; set; } = null;

        /// <summary>
        /// SSH Key Phrase
        /// </summary>
        [Parameter(HelpMessage = "Key phrase to use to open the SSH private key file.")]
        public SecureString KeyPhrase { get; set; } = null;

        /// <summary>
        /// SSH Key Content
        /// </summary>
        [Parameter(HelpMessage = "String array of the content of a OpenSSH key file.")]
        public string[] KeyString { get; set; } = new string[] { };
    }
}
