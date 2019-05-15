// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Storage {
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Key value store interface
    /// </summary>
    public interface IKeyValueStore {

        /// <summary>
        /// Read the value of the key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="contentType"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<string> GetKeyValueAsync(string key, string contentType,
            CancellationToken ct = default(CancellationToken));

        /// <summary>
        /// Write the value to the key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <param name="contentType"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task SetKeyValueAsync(string key, string value, string contentType, 
            CancellationToken ct = default(CancellationToken));
    }
}