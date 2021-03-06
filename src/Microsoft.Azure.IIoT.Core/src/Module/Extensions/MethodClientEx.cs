// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Module {
    using System;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// Method client extensions
    /// </summary>
    public static class MethodClientEx {

        /// <summary>
        /// Call method with json payload.
        /// </summary>
        /// <param name="client"></param>
        /// <param name="deviceId"></param>
        /// <param name="moduleId"></param>
        /// <param name="method"></param>
        /// <param name="json"></param>
        /// <param name="timeout"></param>
        /// <returns></returns>
        public static async Task<string> CallMethodAsync(this IMethodClient client,
            string deviceId, string moduleId, string method, string json,
            TimeSpan? timeout = null) {
            var response = await client.CallMethodAsync(deviceId, moduleId, method,
                json == null ? null : Encoding.UTF8.GetBytes(json),
                ContentEncodings.MimeTypeUaJson, timeout);
            return response.Length == 0 ? null : Encoding.UTF8.GetString(response);
        }
    }
}
