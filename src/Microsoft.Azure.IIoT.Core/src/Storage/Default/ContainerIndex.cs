// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Storage.Default {
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.IIoT.Storage;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// A etag based incremental index factory
    /// </summary>
    public sealed class ContainerIndex : IContainerIndex, IItemContainer {

        /// <inheritdoc/>
        public string Name => _container.Name;

        /// <summary>
        /// Create index on top of container
        /// </summary>
        /// <param name="container"></param>
        public ContainerIndex(IItemContainer container) {
            _container = container;
            _applications = container.AsDocuments();
            _id = $"__idx_doc_{container.Name}__";
        }

        /// <inheritdoc/>
        public async Task<uint> AllocateAsync(CancellationToken ct) {
            while (true) {
                // Get current value
                var cur = await _applications.GetAsync<Bitmap>(_id, ct);
                if (cur == null) {
                    // Add new index
                    try {
                        var idx = new Bitmap();
                        var value = idx.Allocate();
                        await _applications.AddAsync(idx, ct, _id, null);
                        return value;
                    }
                    catch (ConflictingResourceException) {
                        // Doc was added from another process/thread
                    }
                }
                else {
                    // Get next free index
                    try {
                        var idx = new Bitmap(cur.Value);
                        var value = idx.Allocate();
                        await _applications.ReplaceAsync(cur, idx, ct);
                        return value; // Success - return index
                    }
                    catch (ResourceOutOfDateException) {
                        // Etag is no match
                    }
                }
            }
        }

        /// <inheritdoc/>
        public async Task FreeAsync(uint index, CancellationToken ct) {
            while (true) {
                // Get current value
                var cur = await _applications.GetAsync<Bitmap>(_id, ct);
                if (cur == null) {
                    return;
                }
                try {
                    var idx = new Bitmap(cur.Value);
                    if (idx.Free(index)) {
                        await _applications.ReplaceAsync(cur, idx, ct);
                    }
                    return;
                }
                catch (ResourceOutOfDateException) {
                    // Etag is no match - try again to free
                }
            }
        }

        /// <inheritdoc/>
        public IDocuments AsDocuments() => _container.AsDocuments();

        /// <inheritdoc/>
        public IGraph AsGraph() => _container.AsGraph();

        private readonly IItemContainer _container;
        private readonly IDocuments _applications;
        private readonly string _id;
    }
}
