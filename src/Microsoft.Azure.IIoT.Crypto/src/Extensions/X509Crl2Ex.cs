// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Crypto.Models {
    using Microsoft.Azure.IIoT.Crypto.Utils;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.X509;
    using Org.BouncyCastle.X509.Extension;
    using System;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Crl extensions
    /// </summary>
    public static class X509Crl2Ex {

        /// <summary>
        /// Create crl from memory
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static X509Crl2 Parse(byte[] buffer) {
            var parsed = new X509CrlParser().ReadCrl(buffer);
            var updateTime = parsed.ThisUpdate;
            var nextUpdateTime = parsed.NextUpdate == null ?
                DateTime.MinValue : parsed.NextUpdate.Value;
            var issuer = FixUpIssuer(parsed.IssuerDN.ToString());
            return new X509Crl2(issuer, updateTime, nextUpdateTime, buffer);
        }

        /// <summary>
        /// Verifies the signature on the CRL.
        /// </summary>
        /// <param name="crl"></param>
        /// <param name="issuer"></param>
        public static void Validate(this X509Crl2 crl, X509Certificate2 issuer) {
            var bccert = new X509CertificateParser().ReadCertificate(issuer.RawData);
            crl.ToX509Crl().Verify(bccert.GetPublicKey());
        }

        /// <summary>
        /// Verifies the signature on the CRL.
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="crl"></param>
        /// <returns></returns>
        public static bool HasValidSignature(this X509Crl2 crl, X509Certificate2 issuer) {
            try {
                Validate(crl, issuer);
                return true;
            }
            catch (Exception) {
                return false;
            }
        }

        /// <summary>
        /// Returns true the certificate is in the CRL.
        /// </summary>
        /// <param name="crl"></param>
        /// <param name="issuer"></param>
        /// <param name="certificate"></param>
        /// <returns></returns>
        public static bool IsRevoked(this X509Crl2 crl, X509Certificate2 issuer, 
            X509Certificate2 certificate) {
            // check that the issuer matches.
            if (issuer == null || !CertUtils.CompareDistinguishedName(certificate.Issuer, issuer.Subject)) {
                throw new ArgumentException("Certificate was not created by the CRL issuer.");
            }
            var bccert = new X509CertificateParser().ReadCertificate(certificate.RawData);
            return crl.ToX509Crl().IsRevoked(bccert);
        }

        /// <summary>
        /// Read the Crl number from a X509Crl.
        /// </summary>
        public static BigInteger GetCrlNumber(this X509Crl crl) {
            var crlNumber = BigInteger.One;
            var asn1Object = GetExtensionValue(crl, X509Extensions.CrlNumber);
            if (asn1Object != null) {
                crlNumber = DerInteger.GetInstance(asn1Object).PositiveValue;
            }
            return crlNumber;
        }

        /// <summary>
        /// Convert to bouncy castle crl
        /// </summary>
        /// <param name="crl"></param>
        /// <returns></returns>
        internal static X509Crl2 ToX509Crl2(this X509Crl crl) {
            return Parse(crl.GetEncoded());
        }

        /// <summary>
        /// Convert to bouncy castle crl
        /// </summary>
        /// <param name="crl"></param>
        /// <returns></returns>
        internal static X509Crl ToX509Crl(this X509Crl2 crl) {
            return new X509CrlParser().ReadCrl(crl.RawData);
        }

        /// <summary>
        /// Helper to make issuer match System.Security conventions
        /// </summary>
        /// <param name="issuerDN"></param>
        /// <returns></returns>
        private static string FixUpIssuer(string issuerDN) {
            // replace state ST= with S= 
            issuerDN = issuerDN.Replace("ST=", "S=");
            // reverse DN order 
            var issuerList = CertUtils.ParseDistinguishedName(issuerDN);
            issuerList.Reverse();
            return string.Join(", ", issuerList);
        }

        /// <summary>
        /// Get the value of an extension oid.
        /// </summary>
        private static Asn1Object GetExtensionValue(
            IX509Extension extension, DerObjectIdentifier oid) {
            var asn1Octet = extension.GetExtensionValue(oid);
            if (asn1Octet != null) {
                return X509ExtensionUtilities.FromExtensionValue(asn1Octet);
            }
            return null;
        }
    }
}
