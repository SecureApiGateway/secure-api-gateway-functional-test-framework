package com.forgerock.sapi.gateway.framework.test.factories

import com.forgerock.sapi.gateway.framework.configuration.ProductionTrustedDirectoryConfig

/**
 * Factory to create a configured object that may be used in unit tests of the framework itself
 */
class ProductionTrustedDirectoryConfigFactory {
    companion object {
        fun getValidProductionTrustedDirectoryConfig(): ProductionTrustedDirectoryConfig {
            return ProductionTrustedDirectoryConfig(
                apiClientConfig = ApiClientConfigFactory.getApiClientConfigs(1),
                name = "Mock production directory",
                jwks_uri = "https://fake.com/jwks",
                openidWellKnown = "https://forgerock.com/oidc/.well-known/openid-configuration",
                ssaUrl = "https://forgerock.com/ssa",
                ssaClaimNames = SsaClaimNamesFactory.getSsaClaimsNames(),
                scopesToAccessSsa = "ssa_access"
            )
        }
    }
}