function New-ServiceObject {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [string]$Name
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "New-ServiceObject:"

    $NewObject = [ServiceObject]::new()
    $NewObject.Name = $Name
    $NewObject
}