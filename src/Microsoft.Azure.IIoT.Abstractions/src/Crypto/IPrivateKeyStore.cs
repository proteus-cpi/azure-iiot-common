﻿// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Crypto {
    using Microsoft.Azure.IIoT.Crypto.Models;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Manages private keys by id
    /// </summary>
    public interface IPrivateKeyStore {

        /// <summary>
        /// Imports a Private Key under specified keyId
        /// </summary>
        /// <param name="keyId"></param>
        /// <param name="privateKey"></param>
        /// <param name="encoding"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task ImportKeyAsync(string keyId, byte[] privateKey,
            PrivateKeyEncoding encoding, 
            CancellationToken ct = default);

        /// <summary>
        /// Load Private Key Id
        /// </summary>
        /// <param name="keyId"></param>
        /// <param name="encoding"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<byte[]> GetKeyAsync(string keyId,
            PrivateKeyEncoding encoding, 
            CancellationToken ct = default);

        /// <summary>
        /// Accept Private Key with key Id
        /// </summary>
        /// <param name="keyId"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task DisableKeyAsync(string keyId,
            CancellationToken ct = default);

        /// <summary>
        /// Delete Private Key with key Id
        /// </summary>
        /// <param name="keyId"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task DeleteKeyAsync(string keyId,
            CancellationToken ct = default);
    }
}