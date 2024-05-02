package com.forgerock.sapi.gateway.ob.uk.tests.functional.account.access.consents

import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.data.AccessToken
import uk.org.openbanking.datamodel.account.OBReadConsentResponse1
import uk.org.openbanking.datamodel.common.OBExternalPermissions1Code

interface AccountAccessConsentApi {
    fun createConsent(
        permissions: List<OBExternalPermissions1Code>,
        apiClient: ApiClient,
        apiUnderTest: ApiUnderTest
    ): OBReadConsentResponse1

    fun createConsentAndGetAccessToken(
        permissions: List<OBExternalPermissions1Code>, apiClient: ApiClient,
        apiUnderTest: ApiUnderTest
    ): Pair<OBReadConsentResponse1, AccessToken>

    fun deleteConsent(consentId: String, apiClient: ApiClient, apiUnderTest: ApiUnderTest)

    fun getConsent(consentId: String, apiClient: ApiClient, apiUnderTest: ApiUnderTest): OBReadConsentResponse1
}