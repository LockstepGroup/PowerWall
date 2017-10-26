function Get-PwSsServiceObject {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [string]$ExportedElementXml
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Get-PwSsServiceObject: "

    # Check for path and import
    if (Test-Path $ExportedElementXml) {
        $ExportedElements = Get-Content $ExportedElementXml
    }

    # Setup return Array
    $ReturnArray = @()

    # Exported data should be xml
    $ExportedElements = [xml]$ExportedElements
    $ServiceUdp       = $ExportedElements.generic_import_export.service_udp
    $ServiceTcp       = $ExportedElements.generic_import_export.service_tcp
    $ServiceIp        = $ExportedElements.generic_import_export.service_ip

    #

    function ParseServices {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$True,Position=0)]
            [array]$RawServices,

            [Parameter(Mandatory=$True,Position=1)]
            [string]$Protocol
        )

        $ReturnArray = @()

        foreach ($entry in $RawServices) {
                
                # Initialize the object
                $NewObject    = [ServiceObject]::new()
                $ReturnArray += $NewObject
        
                # Properties that exist on all types
                $NewObject.Name     = $entry.Name
                $NewObject.Comment  = $entry.Comment
                $NewObject.Protocol = $Protocol

                # IP Protocols
                if ($entry.protocol_number) {
                    $NewObject.Protocol = $entry.protocol_number
                }
        
                # Source ports
                if ($entry.min_src_port) {
                    $SourcePort = ""
                    $SourcePort = $entry.min_src_port
                    if ($entry.max_src_port) {
                        $SourcePort += '-' + $entry.max_src_port
                    }
                    $NewObject.SourcePort += $SourcePort
                }
        
                # Destination ports
                if ($entry.min_dst_port) {
                    $DestinationPort = ""
                    $DestinationPort = $entry.min_dst_port
                    if ($entry.max_dst_port) {
                        $DestinationPort += '-' + $entry.max_dst_port
                    }
                    $NewObject.DestinationPort += $DestinationPort
                }
            }
        
            $ReturnArray

    }

    $ReturnArray += ParseServices -RawServices $ServiceUdp -Protocol 'Udp'
    $ReturnArray += ParseServices -RawServices $ServiceTcp -Protocol 'Tcp'
    $ReturnArray += ParseServices -RawServices $ServiceIp  -Protocol 'Ip'

    $ReturnArray
}