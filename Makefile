service := pr/uk-core-functional-tests
repo := europe-west4-docker.pkg.dev/sbat-gcr-develop/sapig-docker-artifact
tests := test


docker:
ifndef tag
	$(warning no tag supplied; latest assumed)
	$(eval TAG=latest)
else
	$(eval TAG=$(shell echo $(tag) | tr A-Z a-z))
endif
ifndef setlatest
	$(warning no setlatest true|false supplied; false assumed)
	$(eval setlatest=false)
endif
	@if [ "${setlatest}" = "true" ]; then \
		docker build -t ${repo}/securebanking/${service}:${TAG} -t ${repo}/securebanking/${service}:latest . ; \
		docker push ${repo}/securebanking/${service} --all-tags; \
    else \
   		docker build  -t ${repo}/securebanking/${service}:${TAG} . ; \
   		docker push ${repo}/securebanking/${service}:${TAG}; \
   	fi;

test:
ifndef apiTestServer
	$(warning no apiTestServer supplied)
	$(eval apiTestServer=dev-core.forgerock.financial)
endif
ifndef apiProvidingOrgID
	$(warning no apiProvidingOrgID supplied)
	$(eval apiProvidingOrgID=0015800001041REAAY)
endif
ifndef apiProvidingSoftwareID
	$(warning no setlatest supplied)
	$(eval apiProvidingSoftwareID=Y6NjA9TOn3aMm9GaPtLwkp)
endif
	@echo "Running tests suite '${tests}'" ; \
	export API_UNDER_TEST_SERVER_TLD=${apiTestServer} ; \
	export API_PROVIDER_ORG_ID=${apiProvidingOrgID} ; \
	export API_PROVIDER_SOFTWARE_ID=${apiProvidingSoftwareID} ; \
	sleep 5s ; \
	./gradlew cleanTest ${tests};