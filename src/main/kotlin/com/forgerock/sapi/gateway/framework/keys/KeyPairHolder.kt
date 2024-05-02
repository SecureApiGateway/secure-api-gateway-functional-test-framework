package com.forgerock.sapi.gateway.framework.keys

import java.security.PrivateKey
import java.security.cert.X509Certificate

data class KeyPairHolder(
    val privateKey: PrivateKey,
    val publicCert: X509Certificate,
    val keyID: String,
    val type: String
)