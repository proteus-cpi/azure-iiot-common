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
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<string> GetKeyValueAsync(
            string key, CancellationToken ct = default);

        /// <summary>
        /// Write the value to the key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<string> SetKeyValueAsync(
            string key, string value, CancellationToken ct = default);
    }
}