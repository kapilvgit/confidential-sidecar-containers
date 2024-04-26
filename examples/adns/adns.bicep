param location string
param registry string
param repository string
param tag string
param ccePolicy string
param managedIDGroup string = resourceGroup().name
param managedIDName string
param serviceFQDN string 
param adnsEndpoint string

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
          port: 80
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
          ports: [
            {
              protocol: 'TCP'
              port: 80
            }
          ]
          resources: {
            requests: {
              memoryInGB: 4
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
          ]
        }
      }
    ]
  }
}

output ids array = [containerGroup.id]
