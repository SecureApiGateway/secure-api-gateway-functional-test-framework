package com.forgerock.sapi.gateway.ob.uk.tests.functional.account.access.consents.api.v3_1_8

import assertk.assertThat
import assertk.assertions.isNotNull
import assertk.assertions.matchesPredicate
import com.forgerock.sapi.gateway.common.constants.OAuth2AuthorizeRequestJwtClaims.Companion.CLAIMS
import com.forgerock.sapi.gateway.common.constants.OAuth2Constants.Companion.NONCE
import com.forgerock.sapi.gateway.common.constants.OAuth2Constants.Companion.STATE
import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.conditions.Status
import com.forgerock.sapi.gateway.framework.data.AccessToken
import com.forgerock.sapi.gateway.framework.data.RequestParameters
import com.forgerock.sapi.gateway.framework.extensions.junit.CreateTppCallback
import com.forgerock.sapi.gateway.framework.utils.GsonUtils
import com.forgerock.sapi.gateway.ob.uk.framework.constants.ACCOUNT_SCOPES
import com.forgerock.sapi.gateway.ob.uk.framework.constants.OB_ACR_CLAIMS
import com.forgerock.sapi.gateway.ob.uk.support.account.AccountFactory
import com.forgerock.sapi.gateway.ob.uk.support.account.AccountRS
import com.forgerock.sapi.gateway.ob.uk.support.discovery.getAccountsApiLinks
import com.forgerock.sapi.gateway.ob.uk.tests.functional.account.access.consents.AccountAccessConsentApi
import com.forgerock.sapi.gateway.uk.common.shared.api.meta.obie.OBVersion
import com.nimbusds.jose.util.JSONObjectUtils
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Assertions.assertEquals
import uk.org.openbanking.datamodel.account.OBReadConsentResponse1
import uk.org.openbanking.datamodel.common.OBExternalPermissions1Code
import java.util.*

class AccountAccessConsent(val version: OBVersion) :
    AccountAccessConsentApi {

    private val accountsApiLinks = getAccountsApiLinks(version)

    fun createAccountAccessConsentTest(apiClient: ApiClient, apiUnderTest: ApiUnderTest) {
        // Given
        val permissions = listOf(OBExternalPermissions1Code.READACCOUNTSDETAIL)
        // When
        val consentResponse = createConsent(permissions, apiClient, apiUnderTest)

        // Then
        assertThat(consentResponse).isNotNull()
        assertThat(consentResponse.data).isNotNull()
        assertEquals(consentResponse.data.permissions, permissions)
        Assertions.assertThat(consentResponse.data.status.toString()).`is`(Status.consentCondition)
    }

    fun deleteAccountAccessConsentTest(apiClient: ApiClient, apiUnderTest: ApiUnderTest) {
        // Given
        val consent = createConsent(listOf(OBExternalPermissions1Code.READACCOUNTSDETAIL), apiClient, apiUnderTest)
        // When
        deleteConsent(consent.data.consentId, apiClient, apiUnderTest)

        // Verify we cannot get the consent anymore
        val error = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            getConsent(
                consent.data.consentId, apiClient, apiUnderTest
            )
        }
        assertThat(error.message).matchesPredicate { msg -> msg!!.contains("\"ErrorCode\":\"OBRI.Consent.Not.Found\",\"Message\":\"Consent not found\"") }
    }

    fun getAccountAccessConsentTest(apiClient: ApiClient, apiUnderTest: ApiUnderTest) {
        // Given
        val originalConsentResponse =
            createConsent(listOf(OBExternalPermissions1Code.READACCOUNTSDETAIL), apiClient, apiUnderTest)
        // When
        val latestConsentResponse = getConsent(originalConsentResponse.data.consentId, apiClient, apiUnderTest)
        // Then
        assertEquals(originalConsentResponse, latestConsentResponse)
    }

    override fun createConsent(
        permissions: List<OBExternalPermissions1Code>,
        apiClient: ApiClient,
        apiUnderTest: ApiUnderTest
    ): OBReadConsentResponse1 {
        val consentRequest = AccountFactory.obReadConsent1(permissions)
        return AccountRS().ConsentCreator().consent(
            accountsApiLinks.CreateAccountAccessConsent,
            consentRequest,
            apiClient, apiUnderTest
        )
    }

    override fun createConsentAndGetAccessToken(
        permissions: List<OBExternalPermissions1Code>,
        apiClient: ApiClient,
        apiUnderTest: ApiUnderTest
    ): Pair<OBReadConsentResponse1, AccessToken> {
        val consent = createConsent(permissions, apiClient, apiUnderTest)
        val obClaims = getOBClaims(consent.data.consentId)
        val responseType = "code id_token" // TODO - refactor so this is passed in by the test so it becomes testable
        val accessToken = apiUnderTest.oauth2Server.getAuthorizationCodeAccessToken(
            apiClient,
            apiUnderTest,
            ACCOUNT_SCOPES,
            apiUnderTest.resourceOwners[0],
            responseType,
            obClaims
        )
        return consent to accessToken
    }


    override fun deleteConsent(consentId: String, apiClient: ApiClient, apiUnderTest: ApiUnderTest) {
        AccountRS().deleteConsent(
            AccountFactory.urlWithConsentId(
                accountsApiLinks.DeleteAccountAccessConsent,
                consentId
            ),
            apiClient, apiUnderTest
        )
    }

    override fun getConsent(
        consentId: String,
        apiClient: ApiClient,
        apiUnderTest: ApiUnderTest
    ): OBReadConsentResponse1 {
        return AccountRS().getConsent(
            AccountFactory.urlWithConsentId(
                accountsApiLinks.GetAccountAccessConsent,
                consentId
            ),
            apiClient, apiUnderTest
        )
    }

    private fun getOBClaims(consentId: String): List<Pair<String, Any>> {
        val idToken = RequestParameters.Claims.IdToken(
            RequestParameters.Claims.IdToken.Acr(true, OB_ACR_CLAIMS),
            RequestParameters.Claims.IdToken.OpenbankingIntentId(true, consentId)
        )
        val userInfo =
            RequestParameters.Claims.Userinfo(
                RequestParameters.Claims.Userinfo.OpenbankingIntentId(
                    true,
                    consentId
                )
            )
        val claims = RequestParameters.Claims(idToken, userInfo)
        val jsonClaims = JSONObjectUtils.parse(GsonUtils.gson.toJson(claims))
        val claimPair = Pair(CLAIMS, jsonClaims)
        val nonce = Pair(NONCE, UUID.randomUUID().toString())
        val state = Pair(STATE, UUID.randomUUID().toString())


        return listOf(claimPair, nonce, state)
    }
}
