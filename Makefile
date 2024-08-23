REGISTRY := karanregistry
RESOURCE_GROUP := karan-adns-rg

sub:
	az account set --subscription "Azure Research Subs" 
	
build:
	./build-adns.sh
	./build-init.sh

push:
	az acr login -n ${REGISTRY}
	docker tag adns:latest ${REGISTRY}.azurecr.io/adns/adns:latest
	docker push ${REGISTRY}.azurecr.io/adns/adns:latest
	docker tag init:latest ${REGISTRY}.azurecr.io/adns/init:latest
	docker push ${REGISTRY}.azurecr.io/adns/init:latest

deploy:
	az deployment group create --name adns-deployment1 --resource-group ${RESOURCE_GROUP} --parameters examples/adns/adns.bicepparam	

inference-fileshare: 
	az deployment group create --name inference-deployment --resource-group ${RESOURCE_GROUP} --parameters examples/adns/inference-fileshare.bicepparam	

inference:  
	az deployment group create --name inference-deployment --resource-group ${RESOURCE_GROUP} --parameters examples/adns/inference.bicepparam	
