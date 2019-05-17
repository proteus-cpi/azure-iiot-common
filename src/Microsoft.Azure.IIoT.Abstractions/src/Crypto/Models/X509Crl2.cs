// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Crypto.Models {
    using System;

    /// <summary>
    /// Represents a crl in lieu of .net having one.
    /// </summary>
    public sealed class X509Crl2 {

        /// <summary>
        /// Create crl
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="updateTime"></param>
        /// <param name="nextUpdateTime"></param>
        /// <param name="rawData"></param>
        public X509Crl2(string issuer, DateTime updateTime,
            DateTime nextUpdateTime, byte[] rawData) {
            Issuer = issuer;
            UpdateTime = updateTime;
            NextUpdateTime = nextUpdateTime;
            RawData = rawData;
        }

        /// <summary>
        /// The subject name of the Issuer for the CRL.
        /// </summary>
        public string Issuer { get; }

        /// <summary>
        /// When the CRL was last updated.
        /// </summary>
        public DateTime UpdateTime { get; }

        /// <summary>
        /// When the CRL is due for its next update.
        /// </summary>
        public DateTime NextUpdateTime { get; }

        /// <summary>
        /// The raw data for the CRL.
        /// </summary>
        public byte[] RawData { get; }
    }
}
