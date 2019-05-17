// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace System.Security.Cryptography.X509Certificates {
    using Org.BouncyCastle.Math;

    /// <summary>
    /// X509 cert extensions
    /// </summary>
    public static class X509Certificate2Ex {

        /// <summary>
        /// Get the serial number from a certificate as BigInteger.
        /// </summary>
        public static BigInteger GetSerialNumberAsBigInteger(this X509Certificate2 certificate) {
            var serialNumber = certificate.GetSerialNumber();
            Array.Reverse(serialNumber);
            return new BigInteger(1, serialNumber);
        }
    }
}
