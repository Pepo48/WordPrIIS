function Test-WordPrIISArtifact {
    param([string]$Path,[string]$Sha256)
    if(!$Path -or $Sha256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'WORDPRIIS:pinned-local-artifact-required'}
    Assert-WordPrIISPlainPath $Path
    if(!(Test-Path -LiteralPath $Path -PathType Leaf) -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $Sha256){throw 'WORDPRIIS:artifact-hash-mismatch'}
}
function Expand-WordPrIISArtifact {
    param([string]$Path,[string]$Sha256,[string]$Destination,[string]$StripPrefix='')
    Assert-WordPrIISPlainPath $Destination
    if(Test-Path -LiteralPath $Destination){throw 'WORDPRIIS:new-destination-required'}
    Add-Type -AssemblyName System.IO.Compression
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $zip=$null;$created=$false
    try {
        $sha=[Security.Cryptography.SHA256]::Create()
        try{$actual=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','')}finally{$sha.Dispose()}
        if($Sha256 -notmatch '^[a-fA-F0-9]{64}$' -or $actual -ine $Sha256){throw 'WORDPRIIS:artifact-hash-mismatch'}
        $stream.Position=0;$zip=New-Object IO.Compression.ZipArchive($stream,[IO.Compression.ZipArchiveMode]::Read,$true)
        if($zip.Entries.Count -gt 20000){throw 'WORDPRIIS:archive-entry-limit'}
        $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $total=[long]0;$entries=New-Object Collections.Generic.List[object]
        foreach($entry in $zip.Entries){
            $name=$entry.FullName.Replace('\','/')
            if($name -match '^/|:|[\x00-\x1f]|(?:^|/)\.\.?(?:/|$)|[. ](?:/|$)|(?:^|/)(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|/|$)' -or (($entry.ExternalAttributes -shr 16) -band 0xf000) -eq 0xa000){throw 'WORDPRIIS:unsafe-archive-entry'}
            if($StripPrefix){if(!$name.StartsWith($StripPrefix,[StringComparison]::Ordinal)){throw 'WORDPRIIS:archive-prefix'};$name=$name.Substring($StripPrefix.Length)}
            if(!$name){continue}
            if(!$seen.Add($name.TrimEnd('/'))){throw 'WORDPRIIS:duplicate-archive-entry'}
            $total+=$entry.Length;if($total -gt 2147483648){throw 'WORDPRIIS:archive-size-limit'}
            $entries.Add(@{entry=$entry;name=$name})
        }
        $null=New-Item -ItemType Directory -Path $Destination;$created=$true
        foreach($item in $entries){
            $target=Join-Path $Destination $item.name
            if($item.name.EndsWith('/')){$null=[IO.Directory]::CreateDirectory($target);continue}
            $null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
            $inputStream=$item.entry.Open();$output=[IO.File]::Open($target,[IO.FileMode]::CreateNew)
            try{$inputStream.CopyTo($output)}finally{$output.Dispose();$inputStream.Dispose()}
        }
    }catch{if($created){Remove-Item -LiteralPath $Destination -Recurse -Force};throw}finally{if($zip){$zip.Dispose()};$stream.Dispose()}
}
