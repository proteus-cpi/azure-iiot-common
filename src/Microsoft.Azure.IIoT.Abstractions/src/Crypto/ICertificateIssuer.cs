// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Crypto {
    using Microsoft.Azure.IIoT.Crypto.Models;
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Issue certificates
    /// </summary>
    public interface ICertificateIssuer {

        /// <summary>
        /// Creates a new ca certificate with specified name and tags it for 
        /// trusted or issuer store.
        /// </summary>
        /// <param name="certificateName"></param>
        /// <param name="subject"></param>
        /// <param name="notBefore"></param>
        /// <param name="notAfter"></param>
        /// <param name="keySize"></param>
        /// <param name="hashSize"></param>
        /// <param name="trusted"></param>
        /// <param name="crlDistributionPoint"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<X509CertificateKeyIdPair> CreateCertificateAsync(string certificateName,
            string subject, DateTime notBefore, DateTime notAfter, int keySize, 
            int hashSize, bool trusted, string crlDistributionPoint, 
            CancellationToken ct = default);

        /// <summary>
        /// Creates a new signed exportable certificate with specified name using
        /// the provided certificate factory
        /// </summary>
        /// <remarks>
        /// The key for the certificate is created in KeyVault, then exported.
        /// In order to delete the created key, the user principal needs
        /// create, get and delete rights for KeyVault certificates
        /// </remarks>
        /// <param name="certificateName"></param>
        /// <param name="subject"></param>
        /// <param name="notBefore"></param>
        /// <param name="notAfter"></param>
        /// <param name="keySize"></param>
        /// <param name="certFactory"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<X509CertificateKeyIdPair> CreateCertificateAsync(string certificateName, 
            string subject, DateTime notBefore, DateTime notAfter, int keySize, 
            Func<RSA, Task<X509Certificate2>> certFactory,
            CancellationToken ct = default);
    }
}