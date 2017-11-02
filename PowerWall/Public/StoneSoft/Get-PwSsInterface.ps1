function Get-PwSsInterface {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$ExportedElementXml,

        [Parameter(Mandatory=$false,Position=1)]
        [string[]]$Cluster
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Get-PwSsInterface: "

    # Check for path and import
    if (Test-Path $ExportedElementXml) {
        $ExportedElements = Get-Content $ExportedElementXml
    }

    # Setup return Array
    $ReturnArray = @()

    # Exported data should be xml
    $ExportedElements = [xml]$ExportedElements
    $Clusters         = $ExportedElements.generic_import_export.fw_cluster
    if ($Cluster) {
        $Clusters = $Clusters | Where-Object { $Cluster -contains $_.Name }
    }

    
    # This makes it easier to write new cmdlets
    $LoopArray = @()
    $LoopArray += $Clusters

    # Regular Expression
    $SubnetRx = [regex] '\/(\d{1,2})'
    
    
    # Start looking for stuff
    :fileloop foreach ($entry in $LoopArray) {

        # Physical interface info
        foreach ($physicalInterface in $entry.physical_interface) {
        
            # Initialize the object
            $NewObject    = [Interface]::new()
            $ReturnArray += $NewObject

            $NewObject.Id         = $physicalInterface.interface_id
            $NewObject.MacAddress = $physicalInterface.macaddress
        }

        # Virtual interface info
        foreach ($virtualInterface in $entry.cluster_virtual_interface) {

            $Id = $virtualInterface.nicid
            $PhysicalLookup = $ReturnArray | Where-Object { $_.Id -eq $Id }

            $PhysicalLookup.Name      = $virtualInterface.name
            $PhysicalLookup.IpAddress = $virtualInterface.mvia_address.address
            $PhysicalLookup.IpAddress += $SubnetRx.Match($virtualInterface.network_value).Value
        }
        
    }

    $ReturnArray
}