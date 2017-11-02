function Get-PwSsRoute {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$ExportedElementXml,

        [Parameter(Mandatory=$false,Position=1)]
        [string[]]$Cluster,

        [Parameter(Mandatory=$True,Position=2)]
        [array]$NetworkObjects,

        [Parameter(Mandatory=$True,Position=3)]
        [array]$Interfaces
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Get-PwSsRoute: "

    # Check for path and import
    if (Test-Path $ExportedElementXml) {
        $ExportedElements = Get-Content $ExportedElementXml
    }

    # Setup return Array
    $ReturnArray = @()

    # Exported data should be xml
    $ExportedElements = [xml]$ExportedElements
    $RoutingNodes     = $ExportedElements.generic_import_export.routing_node
    if ($Cluster) {
        $RoutingNodes = $RoutingNodes | Where-Object { $Cluster -contains $_.Name }
    }

    
    # This makes it easier to write new cmdlets
    $LoopArray = @()
    $LoopArray += $RoutingNodes
    
    
    # Start looking for stuff
    :fileloop foreach ($entry in $LoopArray) {

        # Physical interface info
        foreach ($interface in $entry.interface_rn_level) {

            $NicId = $interface.nicid

            foreach ($gateway in $interface.network_rn_level.gateway_rn_level) {

                foreach ($destination in $gateway.any_rn_level.ne_ref) {
                    $NewObject    = [Route]::new()
                    $ReturnArray += $NewObject
    
                    $NewObject.NextHop     = $gateway.ipaddress
                    $NewObject.Interface   = ($Nics | Where-Object { $_.Id -eq $NicId }).Name
                    $NewObject.Destination = Resolve-PwObject -ObjectToResolve $destination -ObjectList $NetworkObjects
                }
            }
        }
    }

    $ReturnArray
}