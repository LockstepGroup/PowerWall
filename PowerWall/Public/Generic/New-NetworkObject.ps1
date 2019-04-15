function New-NetworkObject {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [string]$Name
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "New-NetworkObject:"

    $NewObject = [NetworkObject]::new()
    $NewObject.Name = $Name
    $NewObject
}