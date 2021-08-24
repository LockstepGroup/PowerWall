function Get-PwSsExpression {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [string]$ExportedElementXml
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Get-PwSsExpression: "

    # Check for path and import
    if (Test-Path $ExportedElementXml) {
        $ExportedElements = Get-Content $ExportedElementXml
    }

    # Setup return Array
    $ReturnArray = @()

    # Exported data should be xml
    $ExportedElements = [xml]$ExportedElements
    $Expression       = $ExportedElements.generic_import_export.expression

    # This makes it easier to write new cmdlets
    $LoopArray  = @()
    $LoopArray += $Expression

    # Process data
    foreach ($entry in $LoopArray) {
        $NewObject    = [SsExpression]::new()
        $ReturnArray += $NewObject

        $NewObject.Name     = $entry.name
        $NewObject.Comment  = $entry.comment
        $NewObject.Operator = $entry.operator
        $NewObject.Value    = $entry.expression_value.ne_ref
    }

    $ReturnArray
}