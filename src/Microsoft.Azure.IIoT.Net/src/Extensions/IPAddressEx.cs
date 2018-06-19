﻿// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace System.Net {
    using Microsoft.Azure.IIoT.Net.Models;

    public static class IPAddressEx {

        /// <summary>
        /// Clone address as v4 address
        /// </summary>
        /// <param name="address"></param>
        /// <returns></returns>
        public static IPv4Address AsV4(this IPAddress address) =>
            address == null ? null : new IPv4Address(address.GetAddressBytes());

        /// <summary>
        /// Clone address
        /// </summary>
        /// <param name="address"></param>
        /// <returns></returns>
        public static IPAddress Copy(this IPAddress address) =>
            address == null ? null : new IPAddress(address.GetAddressBytes());
    }
}