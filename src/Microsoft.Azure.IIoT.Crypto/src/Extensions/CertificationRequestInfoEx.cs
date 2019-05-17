﻿// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Crypto {
    using Org.BouncyCastle.Asn1.Pkcs;
    using Org.BouncyCastle.Pkcs;
    using System;

    /// <summary>
    /// Certificate request info extensions
    /// </summary>
    public static class CertificationRequestInfoEx2 {

        /// <summary>
        /// Convert buffer to request info
        /// </summary>
        /// <param name="certificateRequest"></param>
        /// <returns></returns>
        public static CertificationRequestInfo ToCertificationRequestInfo(
            this byte[] certificateRequest) {
            if (certificateRequest == null) {
                throw new ArgumentNullException(nameof(certificateRequest));
            }
            var pkcs10CertificationRequest = new Pkcs10CertificationRequest(
                certificateRequest);
            if (!pkcs10CertificationRequest.Verify()) {
                throw new FormatException("CSR signature invalid.");
            }
            return pkcs10CertificationRequest.GetCertificationRequestInfo();
        }
    }
}