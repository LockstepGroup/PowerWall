# PowerWall
firewall parser and config generator

## Example
```powershell
$AsaFile = 'running-config.cfg'

$AccessPolicies = Get-PwAsaSecurityPolicy -ConfigPath $AsaFile
$NatPolicies = Get-PwAsaNatPolicy -ConfigPath $AsaFile

$Objects        = Get-PwAsaObject -ConfigPath $AsaFile
$NetworkObjects = $Objects | Where-Object { $_.GetType().Name -eq 'NetworkObject' }
$ServiceObjects = $Objects | Where-Object { $_.GetType().Name -eq 'ServiceObject' }

$ResolvedAccessPolicies = Resolve-PwSecurityPolicy -Policy $AccessPolicies -NetworkObjects $NetworkObjects -ServiceObjects $ServiceObjects -FirewallType 'asa'

# Resolve Network Objects
$ResolvedNetworkObject = foreach ($object in $NetworkObjects) {
    $ResolvedObject = Resolve-PwObject -ObjectToResolve $object.Name -ObjectList $NetworkObjects
    foreach ($robject in $ResolvedObject) {
        $NewObject = New-PwNetworkObject -Name $object.Name
        $NewObject.Comment = $object.Comment
        $NewObject.ResolvedMember = $robject
        $NewObject.MemberOf = $object.MemberOf
        $NewObject.NatSourceInterface = $object.NatSourceInterface
        $NewObject.NatDestinationInterface = $object.NatDestinationInterface
        $NewObject.NatType = $object.NatType
        $NewObject.NatSourceAddress = $object.NatSourceAddress
        $NewObject | Select-Object * -ExcludeProperty Member
    }
}

# Resolve Service Objects
$ResolvedServiceObject = foreach ($object in $ServiceObjects) {
    $ResolvedObject = Resolve-PwObject -ObjectToResolve $object.Name -ObjectList $ServiceObjects
    foreach ($robject in $ResolvedObject) {
        $NewObject = New-PwServiceObject -Name $object.Name
        $NewObject.Comment = $object.Comment
        $NewObject.Protocol = $object.Protocol
        $NewObject.SourcePort = $object.SourcePort
        $NewObject.DestinationPort = $object.DestinationPort
        $NewObject.MemberOf = $object.MemberOf
        $NewObject.ResolvedMember = $robject.Protocol + '/' + $robject.DestinationPort

        $NewObject | Select-Object * -ExcludeProperty Member
    }
}
```