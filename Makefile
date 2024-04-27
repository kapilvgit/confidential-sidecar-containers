REGISTRY := kapilvregistry
RESOURCE_GROUP := kapilv-adns-rg

sub:
	az account set --subscription "Azure Research Subs" 
	
build:
	./build-adns.sh

push:
	az acr login -n ${REGISTRY}
	docker tag adns:latest ${REGISTRY}.azurecr.io/adns/adns:latest
	docker push ${REGISTRY}.azurecr.io/adns/adns:latest

deploy:
	az deployment group create --name adns-deployment --resource-group ${RESOURCE_GROUP} --parameters examples/adns/adns.bicepparam	