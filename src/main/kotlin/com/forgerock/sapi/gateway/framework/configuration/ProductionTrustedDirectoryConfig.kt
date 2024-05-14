package com.forgerock.sapi.gateway.framework.configuration

data class ProductionTrustedDirectoryConfig(
    val apiClientConfig: List<ApiClientConfig>,
    var name: String,
    var jwks_uri: String,
    var openidWellKnown: String,
    var ssaUrl: String,
    val ssaClaimNames: SsaClaimNames,
    var scopesToAccessSsa: String
)