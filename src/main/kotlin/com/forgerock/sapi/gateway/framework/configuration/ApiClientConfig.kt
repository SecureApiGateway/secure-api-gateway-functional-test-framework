package com.forgerock.sapi.gateway.framework.configuration

data class ApiClientConfig(
    val orgId: String,
    val softwareId: String,

    val publicTransportKeyID: String,
    val publicTransportPemPath: String,
    val privateTransportPemPath: String,

    val publicSigningKeyID: String,
    val publicSigningPemPath: String,
    val privateSigningPemPath: String
)