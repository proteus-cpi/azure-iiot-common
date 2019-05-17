// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.Crypto.KeyVault.Runtime {
    using Microsoft.Azure.IIoT.Crypto.KeyVault;
    using Microsoft.Azure.IIoT.Utils;
    using Microsoft.Extensions.Configuration;

    /// <inheritdoc/>
    public class KeyVaultConfig : ConfigBase, IKeyVaultConfig {

        /// <summary>
        /// Key Vault configuration
        /// </summary>
        private const string kOpcVault_KeyVaultBaseUrlKey = "KeyVault:BaseUrl";
        private const string kOpcVault_KeyVaultResourceIdKey = "KeyVault:ResourceId";
        private const string kOpcVault_KeyVaultIsHsmKey = "KeyVault:IsHsm";

        /// <inheritdoc/>
        public string KeyVaultBaseUrl => GetStringOrDefault(kOpcVault_KeyVaultBaseUrlKey,
            GetStringOrDefault("KEYVAULT__BASEURL",
                GetStringOrDefault("PCS_KEYVAULT_CONFIGURATION_URI"))).Trim();
        /// <inheritdoc/>
        public string KeyVaultResourceId => GetStringOrDefault(kOpcVault_KeyVaultResourceIdKey,
            GetStringOrDefault("KEYVAULT__RESOURCEID",
                "https://vault.azure.net")).Trim();
        /// <inheritdoc/>
        public bool KeyVaultIsHsm => GetBoolOrDefault(
            kOpcVault_KeyVaultIsHsmKey, true);

        /// <summary>
        /// Configuration constructor
        /// </summary>
        /// <param name="configuration"></param>
        public KeyVaultConfig(IConfigurationRoot configuration) :
            base(configuration) {
        }
    }
}