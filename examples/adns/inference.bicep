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
param fileShareName string
param storageAccountName string

var dnsName = deployment().name
var dnsUrl = '${dnsName}.${location}.azurecontainer.io'

var storageAccountKey = ''

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
          ports: [
            {
              protocol: 'TCP'
              port: 443
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
            {
              name: 'SERVICE_PORT'
              value: '${servicePort}'
            }
          ]
        }
      }
      {
        name: 'inference-server'
        properties: {
          image: 'kapilvaswani/inference-server:latest'
          command: [
            'tritonserver'
            '--model-repository=/mnt/models'
          ]
          ports: [
            {
              protocol: 'TCP'
              port: servicePort
            }
          ]
          resources: {
            requests: {
              cpu: 4
              memoryInGB: 12
            }
          }
          volumeMounts: [
            {
              mountPath: '/mnt/models'
              name: 'modelsvolume'
            }
          ]
        }
      }
    ]
    volumes: [
      {
        name: 'modelsvolume'
        azureFile: {
          storageAccountName: storageAccountName
          storageAccountKey: storageAccountKey
          shareName: fileShareName
        }
      }
    ]
  }
}

output ids array = [containerGroup.id]

