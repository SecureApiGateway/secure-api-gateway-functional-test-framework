package com.forgerock.sapi.gateway.framework.trusteddirectory.certificateproviders

import com.forgerock.sapi.gateway.framework.configuration.DevelopmentTrustedDirectoryConfig
import com.forgerock.sapi.gateway.framework.http.fuel.jsonBody
import com.forgerock.sapi.gateway.framework.http.fuel.responseObject
import com.forgerock.sapi.gateway.framework.keys.KeyPairHolder
import com.forgerock.sapi.gateway.framework.trusteddirectory.CertificateProvider
import com.forgerock.sapi.gateway.framework.utils.KeyUtils
import com.github.kittinunf.fuel.Fuel
import com.github.kittinunf.fuel.core.Headers
import com.github.kittinunf.fuel.core.isSuccessful
import com.nimbusds.jose.jwk.JWKSet
import javax.net.ssl.SSLSocketFactory

class ApiCertificateProvider(val devDirectoryConfig: DevelopmentTrustedDirectoryConfig) :
    CertificateProvider {

    val jwkSet: Map<String, Object>
    private lateinit var transportKeys: KeyPairHolder
    private lateinit var signingKeys: KeyPairHolder
    private lateinit var transportPublicCertPemString: String
    private lateinit var transportPrivateKeyPemString: String


    init {
        val getKeysUrl = devDirectoryConfig.getKeysUrl
        val (_, response, result) = Fuel.post(getKeysUrl)
            .jsonBody("{\"org_id\": \"PSDGB-FFA-5f563e89742b2800145c7da1\",\"org_name\": \"Acme Fintech\"}")
            .header(Headers.CONTENT_TYPE, "application/json")
            .responseObject<Map<String, Object>>()

        if (response.isSuccessful) {
            jwkSet = result.get()
            println("jwkSet: $jwkSet")
            println("Obtained keys from ${devDirectoryConfig.getKeysUrl}")
        } else {
            throw Exception("Failed to obtain keys from ${getKeysUrl}. Error was ${response.statusCode}, $result.get()")
        }
    }

    override fun getTransportKeys(): KeyPairHolder {
        if (!this::transportKeys.isInitialized) {
            val getTransportPemsUrl = devDirectoryConfig.getTransportPemsUrl
            val (_, response, result) = Fuel.post(getTransportPemsUrl)
                .jsonBody(jwkSet)
                .header(Headers.CONTENT_TYPE, "application.json")
                .response()

            if (response.isSuccessful) {
                val transportCerts = result.get()
                println("Transport Certs are $transportCerts")
                transportKeys = getKeyPairHolder(transportCerts.decodeToString(), "tls")
            } else {
                throw Exception("Failed to understand response from $getTransportPemsUrl")
            }
        }
        return transportKeys
    }

    override fun getSigningKeys(): KeyPairHolder {
        if (!this::signingKeys.isInitialized) {
            val getSigningKeysUrl = devDirectoryConfig.getSigningPemsUrl
            val (_, response, result) = Fuel.post(getSigningKeysUrl)
                .jsonBody(jwkSet)
                .header(Headers.CONTENT_TYPE, "application.json")
                .response()

            if (response.isSuccessful) {
                val signingCerts = result.get()
                println("Signing Certs are $signingCerts")
                signingKeys = getKeyPairHolder(signingCerts.decodeToString(), "sig")
            } else {
                throw Exception("Failed to understand response from $getSigningKeysUrl")
            }
        }
        return signingKeys
    }

    override fun getSocketFactory(): SSLSocketFactory {
        var ks = KeyUtils.getKeyStore(
            privatePem = this.transportPrivateKeyPemString.byteInputStream(),
            publicPem = this.transportPublicCertPemString.byteInputStream()
        )
        var socketFactory = KeyUtils.getSocketFactory(ks)
        return socketFactory
    }

    private fun getKeyPairHolder(pemKeyPair: String, certUse: String): KeyPairHolder {
        val splitAtIndex = pemKeyPair.indexOf("-----BEGIN RSA PRIVATE KEY-----")
        transportPublicCertPemString = pemKeyPair.subSequence(0, splitAtIndex).toString()
        transportPrivateKeyPemString = pemKeyPair.subSequence(splitAtIndex, pemKeyPair.length).toString()
        val publicCert = KeyUtils.readX509PublicCertificate(transportPublicCertPemString)
        val privateKey = KeyUtils.readPKS8PrivateKey(transportPrivateKeyPemString)

        return KeyPairHolder(privateKey, publicCert, getKid(certUse), certUse)
    }

    private fun getKid(certType: String): String {
        val jwkSetObj: JWKSet = JWKSet.parse(jwkSet)
        for (jwkSet in jwkSetObj.keys) {
            if (jwkSet.keyUse.toString() == certType) {
                return jwkSet.keyID
            }
        }
        throw Exception("No cert of use $certType found in jwks")
    }
}