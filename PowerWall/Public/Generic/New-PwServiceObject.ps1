function New-PwServiceObject {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [string]$Protocol,

        [Parameter(Mandatory = $false)]
        [string]$DestinationPort
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "New-ServiceObject:"

    $NewObject = [ServiceObject]::new()
    $NewObject.Name = $Name

    if ($Protocol) {
        $NewObject.Protocol = $Protocol
    }

    if ($DestinationPort) {
        $NewObject.DestinationPort = $DestinationPort
    }

    $NewObject
}