package com.forgerock.sapi.gateway.ob.uk.tests.functional.account.statements.api.v3_1_8

import assertk.assertThat
import assertk.assertions.*
import com.forgerock.sapi.gateway.framework.api.ApiUnderTest
import com.forgerock.sapi.gateway.framework.apiclient.ApiClient
import com.forgerock.sapi.gateway.framework.extensions.junit.CreateTppCallback
import com.forgerock.sapi.gateway.ob.uk.support.account.AccountRS
import com.forgerock.sapi.gateway.ob.uk.tests.functional.account.access.BaseAccountApi3_1_8
import com.forgerock.sapi.gateway.uk.common.shared.api.meta.obie.OBVersion
import com.github.kittinunf.fuel.core.FuelError
import uk.org.openbanking.datamodel.account.OBReadAccount6
import uk.org.openbanking.datamodel.account.OBReadStatement2
import uk.org.openbanking.datamodel.common.OBExternalPermissions1Code

class GetAccountStatementFile(version: OBVersion, tppResource: CreateTppCallback.TppResource) :
    BaseAccountApi3_1_8(version, tppResource) {

    private val statementConsentPermissions = listOf(
        OBExternalPermissions1Code.READSTATEMENTSBASIC,
        OBExternalPermissions1Code.READSTATEMENTSDETAIL,
        OBExternalPermissions1Code.READACCOUNTSDETAIL
    )

    fun shouldGet_badRequest_StatementFileTest(apiClient: ApiClient, apiUnderTest: ApiUnderTest) {
        // Given
        val (_, accessToken) = accountAccessConsentApi.createConsentAndGetAccessToken(
            statementConsentPermissions,
            apiClient,
            apiUnderTest
        )
        val accounts =
            AccountRS().getAccountsData<OBReadAccount6>(accountsApiLinks.GetAccounts, accessToken, apiClient)

        assertThat(accounts.data).isNotNull()
        assertThat(accounts.data.account[0].accountId).isNotNull()

        val accountStatementDataUrl = accountsApiLinks.GetAccountStatements
            .replace("{AccountId}", accounts.data.account[0].accountId)
        val resultGetAccountStatements = AccountRS().getAccountData<OBReadStatement2>(
            accountStatementDataUrl,
            accessToken,
            accounts.data.account[0].accountId,
            apiClient
        )

        assertThat(resultGetAccountStatements).isNotNull()
        assertThat(resultGetAccountStatements.data.statement[0].statementId).isNotEmpty()

        val accountDataUrl = accountsApiLinks.GetAccountStatementFile
            .replace("{AccountId}", accounts.data.account[0].accountId)
            .replace("{StatementId}", resultGetAccountStatements.data.statement[0].statementId)

        // When
        val result = AccountRS().getAccountStatementFileData(accountDataUrl, accessToken, "*/*", apiClient)

        // Then
        assertThat((result.third.component2() as FuelError).response.statusCode).isEqualTo(400)
        val body = String((result.third.component2() as FuelError).response.data)
        assertThat(body).contains("UK.OBIE.Header.Invalid")
        assertThat(body).contains("Invalid header 'Accept' the only supported value for this operation is 'application/pdf'")
    }

    fun shouldGetStatementFileTest(apiClient: ApiClient, apiUnderTest: ApiUnderTest) {
        // Given
        val (_, accessToken) = accountAccessConsentApi.createConsentAndGetAccessToken(
            statementConsentPermissions,
            apiClient,
            apiUnderTest
        )
        val accounts =
            AccountRS().getAccountsData<OBReadAccount6>(accountsApiLinks.GetAccounts, accessToken, apiClient)

        assertThat(accounts.data).isNotNull()
        assertThat(accounts.data.account[0].accountId).isNotNull()

        val accountStatementDataUrl = accountsApiLinks.GetAccountStatements
            .replace("{AccountId}", accounts.data.account[0].accountId)
        val resultGetAccountStatements = AccountRS().getAccountData<OBReadStatement2>(
            accountStatementDataUrl,
            accessToken,
            accounts.data.account[0].accountId,
            apiClient
        )

        assertThat(resultGetAccountStatements).isNotNull()
        assertThat(resultGetAccountStatements.data.statement[0].statementId).isNotEmpty()

        val accountDataUrl = accountsApiLinks.GetAccountStatementFile
            .replace("{AccountId}", accounts.data.account[0].accountId)
            .replace("{StatementId}", resultGetAccountStatements.data.statement[0].statementId)

        // When
        val result = AccountRS().getAccountStatementFileData(accountDataUrl, accessToken, "application/pdf", apiClient)

        // Then
        assertThat(result.third.get()).isNotNull().isNotEmpty()
        assertThat(result.third.get()).isInstanceOf(ByteArray::class.java)
    }
}