// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace System.Collections.Generic {

    /// <summary>
    /// A simple serializable index
    /// </summary>
    public class Bitmap : List<ulong> {

        /// <summary>
        /// Create bitmap
        /// </summary>
        public Bitmap() {
        }

        /// <summary>
        /// Create a clone
        /// </summary>
        /// <param name="map"></param>
        public Bitmap(Bitmap map) : base(map) {
        }

        /// <summary>
        /// Returns index back so it can be allocated again
        /// </summary>
        /// <param name="index"></param>
        /// <returns>Whether the index was freed</returns>
        public bool Free(uint index) {
            var bit = (int)(index % 64);
            var blockIdx = (int)(index / 64);
            if (blockIdx < Count) {
                if (0 != (this[blockIdx] & (1ul << bit))) {
                    this[blockIdx] &= ~(1ul << bit); // Clear bit
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Get first free unuseds index
        /// </summary>
        /// <returns>The next available unused index</returns>
        public uint Allocate() {
            for (var blockIdx = 0; blockIdx < Count; blockIdx++) {
                if (this[blockIdx] == ulong.MaxValue) {
                    continue; // Full - continue
                }
                // Grab from block
                var block = this[blockIdx];
                for (var bit = 0; bit < 64; bit++) {
                    if (0 == (block & (1ul << bit))) {
                        this[blockIdx] |= 1ul << bit;
                        return (uint)(((uint)blockIdx * 64) + bit);
                    }
                }
            }
            // Add new block
            Add(1);
            return (uint)(Count - 1) * 64;
        }
    }
}
