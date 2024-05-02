package com.forgerock.sapi.gateway.framework.trusteddirectory.certificateproviders

import com.forgerock.sapi.gateway.framework.configuration.ApiClientConfig
import com.forgerock.sapi.gateway.framework.keys.KeyPairHolder
import com.forgerock.sapi.gateway.framework.trusteddirectory.CertificateProvider
import com.forgerock.sapi.gateway.framework.utils.FileUtils
import com.forgerock.sapi.gateway.framework.utils.KeyUtils
import java.io.File
import javax.net.ssl.SSLSocketFactory

class FileCertificateProvider(
    val apiClientConfig: ApiClientConfig,
) : CertificateProvider {

    private lateinit var transportKeys: KeyPairHolder
    private lateinit var signingKeys: KeyPairHolder

    override fun getTransportKeys(): KeyPairHolder {
        if (!this::transportKeys.isInitialized) {
            val publicCert = KeyUtils.readX509PublicCertificate(File(apiClientConfig.publicTransportPemPath))
            val privateKey = KeyUtils.readPKS8PrivateKey(File(apiClientConfig.privateTransportPemPath))
            transportKeys = KeyPairHolder(
                privateKey,
                publicCert,
                apiClientConfig.publicTransportKeyID,
                "tls"
            )
        }
        return transportKeys
    }

    override fun getSigningKeys(): KeyPairHolder {
        if (!this::signingKeys.isInitialized) {
            val publicCertificate = KeyUtils.readX509PublicCertificate(File(apiClientConfig.publicSigningPemPath))
            val privateKey = KeyUtils.readPKS8PrivateKey(File(apiClientConfig.privateSigningPemPath))
            signingKeys = KeyPairHolder(
                privateKey, publicCertificate, apiClientConfig.publicSigningKeyID, "sig"
            )
        }
        return signingKeys
    }

    override fun getSocketFactory(): SSLSocketFactory {
        var ks = KeyUtils.getKeyStore(
            privatePem = FileUtils().getInputStream(apiClientConfig.privateTransportPemPath),
            publicPem = FileUtils().getInputStream(apiClientConfig.publicTransportPemPath)
        )
        var socketFactory = KeyUtils.getSocketFactory(ks)
        return socketFactory
    }
}