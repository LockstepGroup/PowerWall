function New-PwSecurityPolicy {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [string]$Name
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "New-PwSecurityPolicy:"

    $NewObject = [SecurityPolicy]::new()
    $NewObject.Name = $Name
    $NewObject
}