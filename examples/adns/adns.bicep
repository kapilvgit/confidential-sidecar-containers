param location string
param registry string
param repository string
param tag string
param ccePolicy string
param managedIDGroup string = resourceGroup().name
param managedIDName string
param serviceFQDN string 
param adnsEndpoint string
param servicePort int 

var dnsName = deployment().name
var dnsUrl = '${dnsName}.${location}.azurecontainer.io'

resource containerGroup 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name: deployment().name
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${resourceId(managedIDGroup, 'Microsoft.ManagedIdentity/userAssignedIdentities', managedIDName)}': {}
    }
  }
  properties: {
    osType: 'Linux'
    sku: 'Confidential'
    restartPolicy: 'Never'
    ipAddress: {
      ports: [
        {
          protocol: 'TCP'
          port: 443
        }
      ]
      type: 'Public'
      dnsNameLabel: dnsName
    }
    confidentialComputeProperties: {
      ccePolicy: ccePolicy
    }
    imageRegistryCredentials: [
      {
        server: registry
        identity: resourceId(managedIDGroup, 'Microsoft.ManagedIdentity/userAssignedIdentities', managedIDName)
      }
    ]
    containers: [
      {
        name: 'adns'
        properties: {
          image: '${registry}/${repository}/adns:${tag}'
          securityContext: {
            privileged: true
          }
          ports: [
            {
              protocol: 'TCP'
              port: 443
            }
          ]
          resources: {
            requests: {
              memoryInGB: 2
              cpu: 1
            }
          }
          environmentVariables: [
            {
              name: 'SERVICE_FQDN'
              value: serviceFQDN
            }
            {
              name: 'DNS_URL'
              value: dnsUrl
            }
            {
              name: 'ADNS_ENDPOINT'
              value: adnsEndpoint
            }
            {
              name: 'SERVICE_PORT'
              value: '${servicePort}'
            }
          ]
        }
      }
      {
        name: 'aci-helloworld'
        properties: {
          image: 'mcr.microsoft.com/azuredocs/aci-helloworld'
          ports: [
            {
              protocol: 'TCP'
              port: servicePort
            }
          ]
          resources: {
            requests: {
              cpu: 1
              memoryInGB: 12
            }
          }
        }
      }
    ]
    initContainers: [
      {
        name: 'init-iptables'
        properties: {
          image: '${registry}/${repository}/init:${tag}'
          securityContext: {
            privileged: true
          }
        }
      }
    ]
  }
}

output ids array = [containerGroup.id]
