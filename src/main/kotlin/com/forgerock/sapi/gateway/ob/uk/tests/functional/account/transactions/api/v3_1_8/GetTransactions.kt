package com.forgerock.sapi.gateway.ob.uk.tests.functional.account.transactions.api.v3_1_8

import assertk.assertThat
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.extensions.junit.CreateTppCallback
import com.forgerock.sapi.gateway.ob.uk.support.account.AccountRS
import com.forgerock.sapi.gateway.ob.uk.tests.functional.account.access.BaseAccountApi3_1_8
import com.forgerock.sapi.gateway.uk.common.shared.api.meta.obie.OBVersion
import uk.org.openbanking.datamodel.account.OBReadTransaction6
import uk.org.openbanking.datamodel.common.OBExternalPermissions1Code

class GetTransactions(version: OBVersion, tppResource: CreateTppCallback.TppResource) :
    BaseAccountApi3_1_8(version, tppResource) {

    fun shouldGetTransactionsTest(apiClient: ApiClient, apiUnderTest: ApiUnderTest) {
        // Given
        val permissions = listOf(
            OBExternalPermissions1Code.READACCOUNTSDETAIL,
            OBExternalPermissions1Code.READTRANSACTIONSCREDITS,
            OBExternalPermissions1Code.READTRANSACTIONSDEBITS,
            OBExternalPermissions1Code.READTRANSACTIONSDETAIL
        )
        val (_, accessToken) = accountAccessConsentApi.createConsentAndGetAccessToken(
            permissions,
            apiClient,
            apiUnderTest
        )

        // When
        val result = AccountRS().getAccountsData<OBReadTransaction6>(
            accountsApiLinks.GetTransactions,
            accessToken, apiClient
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data.transaction).isNotEmpty()
    }
}