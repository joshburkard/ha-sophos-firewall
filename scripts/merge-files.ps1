Clear-Host

$sourcePath = 'C:\Users\josh\OneDrive - BURKARD.IT\GIT\Privat\HomeAssistant\Sophos_Firewall\custom_components\sophos_firewall'
$destinationPath = ".\all-files\all-files-$( ( Get-Date -Format "yyyyMMdd-HHmmss" ) ).txt"

$files = Get-ChildItem -Path $sourcePath -Recurse -File

function Mask-Passwords {
    param (
        [Parameter(Mandatory = $true)]
        [object]$JsonObject
    )

    foreach ($property in $JsonObject.PSObject.Properties) {
        if ($property.Value -is [System.Management.Automation.PSObject]) {
            # Recurse into nested objects
            Mask-Passwords -JsonObject $property.Value
        } elseif ($property.Value -is [System.Collections.IEnumerable] -and
                -not ($property.Value -is [string])) {
            # Recurse into arrays
            foreach ($item in $property.Value) {
                if ($item -is [System.Management.Automation.PSObject]) {
                    Mask-Passwords -JsonObject $item
                }
            }
        } elseif ($property.Name -match 'password') {
            # Mask password fields (case-insensitive)
            $property.Value = '*****'
        }
    }
}

$i = 0
# $files = $files | Where-Object { $_.DirectoryName -notmatch 'bin' -and $_.DirectoryName -notmatch 'obj' -and $_.DirectoryName -notmatch 'scripts' -and $_.Extension -notmatch 'git' }
# $files = $files | Where-Object { $_.Extension -in @('.sln', '.csproj', '.json', '.cs', '.ps1') }
# $file = $files | Out-GridView -PassThru
foreach ( $file in $files ) {
    Write-Output $file.FullName

    $i++
    if ( $i -gt 1) {
        Out-File -FilePath $destinationPath -InputObject '' -Append
    }
    Out-File -FilePath $destinationPath -InputObject ( ''.PadLeft($file.FullName.Length + 4 , '#') ) -Append
    Out-File -FilePath $destinationPath -InputObject ( '# ' + $file.FullName + ' #' ) -Append
    Out-File -FilePath $destinationPath -InputObject ( ''.PadLeft($file.FullName.Length + 4 , '#') + [Environment]::NewLine ) -Append
    $fileContent = Get-Content -Path $file.FullName -Raw

    if ( $file.Extension -eq '.json' ) {
        $JsonObject = ( $fileContent | ConvertFrom-Json )
        Mask-Passwords -JsonObject $JsonObject
        $fileContent = $JsonObject | ConvertTo-Json -Depth 50
    }
    Out-File -FilePath $destinationPath -InputObject $fileContent -Append
}