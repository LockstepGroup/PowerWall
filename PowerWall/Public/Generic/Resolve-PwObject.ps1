function Resolve-PwObject {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [string[]]$ObjectToResolve,

        [Parameter(Mandatory=$True,Position=0)]
        [array]$ObjectList
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Resolve-PwObject: "
	

}