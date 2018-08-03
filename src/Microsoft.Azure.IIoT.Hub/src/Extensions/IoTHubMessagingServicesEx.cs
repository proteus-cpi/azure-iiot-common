﻿// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Hub {
    using Microsoft.Azure.IIoT.Hub.Models;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public static class IoTHubMessagingServicesEx {

        /// <summary>
        /// Send messages for device
        /// </summary>
        /// <param name="deviceId"></param>
        /// <param name="messages"></param>
        /// <returns></returns>
        public static Task SendAsync(this IIoTHubMessagingServices service,
            string deviceId, IEnumerable<DeviceMessageModel> messages) =>
            service.SendAsync(deviceId, null, messages);
    }
}