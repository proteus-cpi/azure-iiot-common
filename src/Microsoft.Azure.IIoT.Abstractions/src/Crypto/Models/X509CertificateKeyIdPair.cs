// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Crypto.Models {
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// A Certificate and private key handle
    /// </summary>
    public class X509CertificateKeyIdPair {

        /// <summary>
        /// Certificate
        /// </summary>
        public X509Certificate2 Certificate { get; set; }

        /// <summary>
        /// Key identifier to look up a private key
        /// </summary>
        public string KeyIdentifier { get; set; }
    }
}

