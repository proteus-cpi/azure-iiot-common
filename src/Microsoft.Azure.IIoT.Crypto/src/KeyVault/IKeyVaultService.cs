// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Crypto.KeyVault {
    using Microsoft.Azure.IIoT.Storage;

    /// <summary>
    /// Key vault service services
    /// </summary>
    public interface IKeyVaultService : IKeyValueStore, IDigestSigner, 
        ICertificateStore, ICertificateIssuer, ITrustListRegistry {
    }
}