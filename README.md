# PowerWall
firewall parser and config generator

## Example
```powershell
$AsaFile = 'running-config.cfg'

$AccessLists = Get-PwAsaSecurityPolicy -ConfigPath $AsaFile


$Objects        = Get-PwAsaObject -ConfigPath $AsaFile
$NetworkObjects = $Objects | Where-Object { $_.GetType().Name -eq 'NetworkObject' }
$ServiceObjects = $Objects | Where-Object { $_.GetType().Name -eq 'ServiceObject' }

$rules = Resolve-PwSecurityPolicy -Policy $AccessLists -NetworkObjects $NetworkObjects -ServiceObjects $ServiceObjects -FirewallType 'asa'
```
