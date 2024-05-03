package com.forgerock.sapi.gateway.framework.configuration

data class ApiClientConfig(
    var orgId: String,
    var softwareId: String,

    var publicTransportKeyID: String,
    var publicTransportPemPath: String,
    var privateTransportPemPath: String,

    var publicSigningKeyID: String,
    var publicSigningPemPath: String,
    var privateSigningPemPath: String
)