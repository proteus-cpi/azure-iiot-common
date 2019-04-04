// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Http {
    using Microsoft.Azure.IIoT.Http.Default;
    using Serilog;
    using System;
    using System.Linq;
    using System.Net.Sockets;
    using System.Threading.Tasks;
    using Xunit;

    public class HttpClientTests {

        [Fact]
        public async Task UnixDomainSocketHttpClientTest() {
            var logger = LogEx.Trace();
            IHttpClient client = new HttpClient(new HttpClientFactory(logger), logger);
            var request = client.NewRequest(new Uri("unix:///var/test/unknown.sock"));
            try {
                await client.GetAsync(request);
                Assert.True(false);
            }
            catch (SocketException ex) {
                Assert.True(true);
                Assert.NotNull(ex);
            }
            catch {
                Assert.True(false);
            }
        }

        [Fact]
        public void UnixDomainSocketHttpRequestTest() {
            var logger = LogEx.Trace();
            IHttpClient client = new HttpClient(new HttpClientFactory(logger), logger);
            var request = client.NewRequest(new Uri("unix:///var/test/unknown.sock"));

            Assert.True(request.Headers.Contains(HttpHeader.UdsPath));
            var path = request.Headers.GetValues(HttpHeader.UdsPath).First();
            Assert.Equal("/var/test/unknown.sock", path);
        }
    }
}
