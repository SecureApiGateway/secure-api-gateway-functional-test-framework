package com.forgerock.sapi.gateway.framework.test.factories

import com.forgerock.sapi.gateway.framework.configuration.ApiClientConfig
import com.forgerock.sapi.gateway.framework.trusteddirectory.CertificateProvider
import com.forgerock.sapi.gateway.framework.trusteddirectory.certificateproviders.FileCertificateProvider

class CertificateProviderFactory {
    companion object {
        fun getValidCertificateProvider(): CertificateProvider {
            val apiClientConfig = ApiClientConfig(
                orgId = "0015800001041REAAY",
                softwareId = "Y6NjA9TOn3aMm9GaPtLwkp",
                publicTransportKeyID = "52TVNALuXKCYzvxgBALeDVp966I",
                publicTransportPemPath = "./certificates/OBWac.pem",
                privateTransportPemPath = "./certificates/OBWac.key",
                publicSigningKeyID = "qfL4CT5GrVgoyXNQtUjF5TIVOXA",
                publicSigningPemPath = "./certificates/OBSeal.pem",
                privateSigningPemPath = "./certificates/OBSeal.key"
            )

            return FileCertificateProvider(apiClientConfig)
        }
    }
}