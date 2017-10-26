function Get-PwSsFirewallPolicy {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [string]$ExportedElementXml
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Get-PwSsFirewallPolicy: "

    # Check for path and import
    if (Test-Path $ExportedElementXml) {
        $ExportedElements = Get-Content $ExportedElementXml
    }

    # Setup return Array
    $ReturnArray = @()

    # Exported data should be xml
    $ExportedElements = [xml]$ExportedElements
    $FirewallPolicy   = $ExportedElements.generic_import_export.fw_policy

    # This makes it easier to write new cmdlets
    $LoopArray  = @()
    $LoopArray += $FirewallPolicy

    # Process data
    foreach ($entry in $LoopArray) {
        $AccessList = $entry.name
        foreach ($rule in $entry.access_entry.rule_entry) {
            $global:testing = $entry
            # Initialize the object
            $NewObject    = [SecurityRule]::new("")
            $ReturnArray += $NewObject

            $NewObject.AccessList = $AccessList

            # disabled
            if ($rule.is_disabled -eq 'true') {
                $NewObject.Enabled = $false
            }

            # Source/destination/service
            $NewObject.Source      = $rule.access_rule.match_part.match_sources.match_source_ref.value
            $NewObject.Destination = $rule.access_rule.match_part.match_destinations.match_destination_ref.value
            $NewObject.Service     = $rule.access_rule.match_part.match_services.match_service_ref.value

        }
    }


    $ReturnArray
}

<#
    [string]$AccessList
    [int]$Number
    [string]$Action
    
    [string]$SourceInterface
    [string]$DestinationInterface
    
    [string]$Source
    [string]$Destination
    
    [string]$Protocol
    [string]$SourcePort
    [string]$DestinationPort
    
    [string]$PacketState
    [string]$RejectWith
    [string]$IcmpType
    [string]$Enabled
#>