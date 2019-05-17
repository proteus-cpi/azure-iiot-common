// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Crypto {
    using Microsoft.Azure.IIoT.Crypto.Models;
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Revoke certificate and create crl
    /// </summary>
    public interface ICertificateRevoker { 

        /// <summary>
        /// Revoke certificates.
        /// The CRL number is increased by one and the new CRL is returned.
        /// </summary>
        /// <param name="issuerCertificate">Issuer</param>
        /// <param name="issuerCrls">Existing crls</param>
        /// <param name="revokedCertificates">Certificates to revoke</param>
        /// <param name="thisUpdate"></param>
        /// <param name="nextUpdate"></param>
        /// <param name="hashSize"></param>
        /// <returns></returns>
        X509Crl2 RevokeCertificate(X509CertificateKeyIdPair issuerCertificate, 
            IEnumerable<X509Crl2> issuerCrls, X509Certificate2Collection revokedCertificates,
            DateTime thisUpdate, DateTime nextUpdate, uint hashSize);

        /// <summary>
        /// Create empty crl signed by the issuer certificate
        /// </summary>
        /// <param name="issuerCertificate">Issuer</param>
        /// <param name="thisUpdate"></param>
        /// <param name="nextUpdate"></param>
        /// <returns></returns>
        X509Crl2 CreateCrl(X509CertificateKeyIdPair issuerCertificate,
            DateTime thisUpdate, DateTime nextUpdate);
    }
}