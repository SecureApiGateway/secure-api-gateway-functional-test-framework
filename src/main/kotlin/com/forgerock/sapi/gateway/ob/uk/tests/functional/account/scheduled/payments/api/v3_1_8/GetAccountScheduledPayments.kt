package com.forgerock.sapi.gateway.ob.uk.tests.functional.account.scheduled.payments.api.v3_1_8

import assertk.assertThat
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.configuration.USER_ACCOUNT_ID
import com.forgerock.sapi.gateway.framework.extensions.junit.CreateTppCallback
import com.forgerock.sapi.gateway.ob.uk.support.account.AccountFactory
import com.forgerock.sapi.gateway.ob.uk.support.account.AccountRS
import com.forgerock.sapi.gateway.ob.uk.tests.functional.account.access.BaseAccountApi3_1_8
import com.forgerock.sapi.gateway.uk.common.shared.api.meta.obie.OBVersion
import uk.org.openbanking.datamodel.account.OBReadScheduledPayment3
import uk.org.openbanking.datamodel.common.OBExternalPermissions1Code

class GetAccountScheduledPayments(version: OBVersion, tppResource: CreateTppCallback.TppResource) :
    BaseAccountApi3_1_8(version, tppResource) {

    fun shouldGetAccountScheduledPaymentsTest(apiClient: ApiClient, apiUnderTest: ApiUnderTest) {
        // Given
        val permissions = listOf(
            OBExternalPermissions1Code.READACCOUNTSDETAIL,
            OBExternalPermissions1Code.READSCHEDULEDPAYMENTSDETAIL
        )
        val (_, accessToken) = accountAccessConsentApi.createConsentAndGetAccessToken(
            permissions,
            apiClient,
            apiUnderTest
        )

        // When
        val result = AccountRS().getAccountsData<OBReadScheduledPayment3>(
            AccountFactory.urlWithAccountId(
                accountsApiLinks.GetAccountScheduledPayments,
                USER_ACCOUNT_ID
            ), accessToken, apiClient
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data.scheduledPayment).isNotEmpty()
    }
}