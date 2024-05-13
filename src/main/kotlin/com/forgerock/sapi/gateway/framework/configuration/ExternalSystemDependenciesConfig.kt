package com.forgerock.sapi.gateway.framework.configuration

/**
 * This class is initialized by Jackson from the config file specified in Config.kt
 */
data class ExternalSystemDependenciesConfig(
    val trustedDirectory: ProductionTrustedDirectoryConfig,
    val apiUnderTest: ApiConfig
)
