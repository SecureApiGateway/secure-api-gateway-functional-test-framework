package com.forgerock.sapi.gateway.ob.uk.framework.configuration

// OB directory access token to create an SSA
val OB_SOFTWARE_ID = System.getenv("obSoftwareId") ?: "Y6NjA9TOn3aMm9GaPtLwkp"
val OB_ORGANISATION_ID = System.getenv("obOrganisationId") ?: "0015800001041REAAY"

val UK_OPEN_BANKING_DIRECTORY_TPP_SCOPES = System.getenv("scopesTpp") ?: "ASPSPReadAccess TPPReadAccess AuthoritiesReadAccess"
val UK_OPEN_BANKING_DIRECTORY_ASPSP_SCOPES = System.getenv("scopesAspsp") ?: "ASPSPReadAccess TPPReadAll AuthoritiesReadAccess"
