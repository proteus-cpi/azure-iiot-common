// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Crypto.Default {
    using Microsoft.Azure.IIoT.Crypto.Models;
    using Microsoft.Azure.IIoT.Storage;
    using Serilog;
    using System;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Crl store
    /// </summary>
    public class KeyValueCrlStore : ICrlStore {

        /// <summary>
        /// Create crl store around the key value store
        /// </summary>
        /// <param name="kvStore">The key value store.</param>
        /// <param name="logger">The logger.</param>
        public KeyValueCrlStore(IKeyValueStore kvStore, ILogger logger) {
            _kvStore = kvStore;
            _logger = logger;
        }

        /// <inheritdoc/>
        public async Task ImportCrlAsync(string certificateName, string thumbPrint,
            X509Crl2 crl, CancellationToken ct) {
            var crlId = GetCrlId(certificateName, thumbPrint);
            await _kvStore.SetKeyValueAsync(crlId, Convert.ToBase64String(crl.RawData), 
                crl.UpdateTime, null, ContentEncodings.MimeTypeCrl, ct);
        }

        /// <inheritdoc/>
        public async Task<X509Crl2> GetCrlAsync(string certificateName, string thumbPrint,
            CancellationToken ct) {
            var crlId = GetCrlId(certificateName, thumbPrint);
            var value = await _kvStore.GetKeyValueAsync(crlId, 
                ContentEncodings.MimeTypeCrl, ct);
            return X509Crl2Ex.Parse(Convert.FromBase64String(value));
        }

        /// <summary>
        /// Get crl name
        /// </summary>
        /// <param name="certificateName"></param>
        /// <param name="thumbprint"></param>
        /// <returns></returns>
        private static string GetCrlId(string certificateName, string thumbprint) {
            return certificateName + "Crl" + thumbprint;
        }

        private readonly IKeyValueStore _kvStore;
        private readonly ILogger _logger;
    }
}

