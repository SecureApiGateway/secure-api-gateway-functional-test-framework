package com.forgerock.sapi.gateway.framework.trusteddirectory

import com.forgerock.sapi.gateway.framework.keys.KeyPairHolder
import javax.net.ssl.SSLSocketFactory

interface CertificateProvider {
    fun getTransportKeys(): KeyPairHolder
    fun getSigningKeys(): KeyPairHolder
    fun getSocketFactory(): SSLSocketFactory
}