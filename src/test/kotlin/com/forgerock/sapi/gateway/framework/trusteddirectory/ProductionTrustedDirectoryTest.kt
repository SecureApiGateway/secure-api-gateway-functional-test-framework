package com.forgerock.sapi.gateway.framework.trusteddirectory

import assertk.assertThat
import assertk.assertions.isSameAs
import com.forgerock.sapi.gateway.framework.oauth.OAuth2Server
import com.forgerock.sapi.gateway.framework.test.factories.CertificateProviderFactory
import com.forgerock.sapi.gateway.framework.test.factories.ProductionTrustedDirectoryConfigFactory
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito

class ProductionTrustedDirectoryTest {

    lateinit var productionTrustedDirectory: ProductionTrustedDirectory
    lateinit var mockOauth2Server: OAuth2Server

    @BeforeEach
    fun beforeEach() {
        val mockSoftwareStatementProvider = Mockito.mock(SoftwareStatementProvider::class.java)
        val productionTrustedDirectoryConfig =
            ProductionTrustedDirectoryConfigFactory.getValidProductionTrustedDirectoryConfig()
        val mockTransportCertProvider: CertificateProvider = CertificateProviderFactory.getValidCertificateProvider()
        val mockSigningKeyCertProvider: CertificateProvider = CertificateProviderFactory.getValidCertificateProvider()
        mockOauth2Server = Mockito.mock(OAuth2Server::class.java)
        productionTrustedDirectory = ProductionTrustedDirectory(
            productionTrustedDirectoryConfig = productionTrustedDirectoryConfig,
            oauth2Server = mockOauth2Server,
            softwareStatementProvider = mockSoftwareStatementProvider,
            transportCertProvider = mockTransportCertProvider,
            signingKeyCertProvider = mockSigningKeyCertProvider
        )
    }

    @Test
    fun getOauth2Server() {
        assertThat(productionTrustedDirectory.oauth2Server).isSameAs(mockOauth2Server)
    }

    @Test
    fun createApiClient() {
    }

    @Test
    fun registerApiClientsWithApiUnderTest() {
    }

    @Test
    fun getSSA() {
    }

    @Test
    fun getProductionTrustedDirectoryConfig() {
    }

    @Test
    fun getSoftwareStatementProvider() {
    }

    @Test
    fun getTransportCertProvider() {
    }

    @Test
    fun getSigningKeyCertProvider() {
    }
}