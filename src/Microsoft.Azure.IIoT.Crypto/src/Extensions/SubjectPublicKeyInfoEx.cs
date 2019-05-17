// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Crypto {
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Asn1.X509;
    using System.Security.Cryptography;

    /// <summary>
    /// SubjectPublicKeyInfo extensions
    /// </summary>
    public static class SubjectPublicKeyInfoEx {

        /// <summary>
        /// Get RSA public key from a key info.
        /// </summary>
        public static RSA GetRSAPublicKey(this SubjectPublicKeyInfo subjectPublicKeyInfo) {
            var asymmetricKeyParameter = PublicKeyFactory.CreateKey(subjectPublicKeyInfo);
            var rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            var rsaKeyInfo = new RSAParameters {
                Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
            };
            var rsa = RSA.Create(rsaKeyInfo);
            return rsa;
        }
    }
}
