#
#
# Windows 11 Normalizer
# (c) 0x8008 2022
#
#

# Enable forms for later use
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

function GetAdmin() {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
}

GetAdmin

# Check admin rights
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    [Void] [System.Windows.Forms.MessageBox]::Show(
        "No admin rights detected. Restart with admin rights.", 
        "[!] 11Normalizer", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    Exit
}

function SetStyle() {
    [CmdletBinding()] param ()
    cmd /c color B
}

SetStyle
$host.UI.RawUI.WindowTitle = "0x8008's 11Normalizer - Log"

Function Error([String]$Message){
    If(($Message -ne $null) -and ($Message.Length -gt 0)){
        $Time = Get-Date -DisplayHint Time
        Write-Host "[$Time] [Error!] $Message" -ForegroundColor Red
    }
}
Function Warning([String]$Message){
    If(($Message -ne $null) -and ($Message.Length -gt 0)){
        $Time = Get-Date -DisplayHint Time
        Write-Host "[$Time] [Warn] $Message" -ForegroundColor Yellow
    }
}
Function Log([String]$Message){
    If(($Message -ne $null) -and ($Message.Length -gt 0)){
        $Time = Get-Date -DisplayHint Time
        Write-Host "[$Time] [Log] $Message" -ForegroundColor Green
    }
}

Try{
    $WhichWindows = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ProductName" -ErrorAction Stop
    If($WhichWindows -notmatch "Windows 10"){
        Error("11Normalizer is only meant for Windows 10 and 11. Press any key to exit...")
        If([System.Console]::ReadKey()){
            Exit
        }
    }
} Catch{
    Error("Getting Windows version failed! Exception $($_). Report this on GitHub. Press any key to exit...")
    If([System.Console]::ReadKey()){
        Exit
    }
}

Try{
    If(((Test-NetConnection www.google.com -Port 80 -InformationLevel "Detailed").TcpTestSucceeded) -eq $false){
        Error("11Normalizer requires a working internet connection. Press any key to exit...")
    }
    If([System.Console]::ReadKey()){
        Exit
    }
} Catch{
    Error("Checking internet connection failed! Exception $($_). Report this on GitHub. Press any key to exit...")
    If([System.Console]::ReadKey()){
        Exit
    }
}


Log("Creating restore point.")
Try{
    Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction Stop
    Checkpoint-Computer -Description "11Normalizer restore point" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
} Catch{
    Error("Restore point creation failed! Exception $($_). Report this on GitHub. Press any key to exit...")
}

Log("Loading GUI...")

# GUI
$MainForm                        = New-Object system.Windows.Forms.Form
$MainForm.ClientSize             = New-Object System.Drawing.Point(255,303)
$MainForm.text                   = "0x8008's 11Normalizer v1"
$MainForm.TopMost                = $false
$MainForm.BackColor              = [System.Drawing.ColorTranslator]::FromHtml("#9b9b9b")
$MainForm.ShowIcon               = $false
$MainForm.FormBorderStyle        = 'Fixed3D'
$MainForm.MaximizeBox            = $false

$Label1                          = New-Object system.Windows.Forms.Label
$Label1.text                     = "11Normalizer"
$Label1.AutoSize                 = $true
$Label1.width                    = 25
$Label1.height                   = 10
$Label1.location                 = New-Object System.Drawing.Point(23,20)
$Label1.Font                     = New-Object System.Drawing.Font('Segoe UI',24,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold -bor [System.Drawing.FontStyle]::Italic))

$ActivateWin                     = New-Object system.Windows.Forms.Button
$ActivateWin.text                = "Activate Windows"
$ActivateWin.width               = 175
$ActivateWin.height              = 30
$ActivateWin.location            = New-Object System.Drawing.Point(40,78)
$ActivateWin.Font                = New-Object System.Drawing.Font('Segoe UI',10)

$DisableBG                       = New-Object system.Windows.Forms.Button
$DisableBG.text                  = "Disable background apps"
$DisableBG.width                 = 175
$DisableBG.height                = 30
$DisableBG.location              = New-Object System.Drawing.Point(40,118)
$DisableBG.Font                  = New-Object System.Drawing.Font('Segoe UI',10)

$DisableCortana                  = New-Object system.Windows.Forms.Button
$DisableCortana.text             = "Disable Cortana"
$DisableCortana.width            = 175
$DisableCortana.height           = 30
$DisableCortana.location         = New-Object System.Drawing.Point(40,158)
$DisableCortana.Font             = New-Object System.Drawing.Font('Segoe UI',10)

$RemoveBloat                     = New-Object system.Windows.Forms.Button
$RemoveBloat.text                = "Remove bloatware apps"
$RemoveBloat.width               = 175
$RemoveBloat.height              = 30
$RemoveBloat.location            = New-Object System.Drawing.Point(40,198)
$RemoveBloat.Font                = New-Object System.Drawing.Font('Segoe UI',10)

$DisableDefender                 = New-Object system.Windows.Forms.Button
$DisableDefender.text            = "Disable Defender"
$DisableDefender.width           = 175
$DisableDefender.height          = 30
$DisableDefender.location        = New-Object System.Drawing.Point(40,239)
$DisableDefender.Font            = New-Object System.Drawing.Font('Segoe UI',10)

$MainForm.controls.AddRange(@($Label1,$ActivateWin,$DisableBG,$DisableCortana,$RemoveBloat,$DisableDefender))

Log("Initialized successfully.")

$ActivateWin.Add_Click({
    Log("Activating Windows...")
    &cscript //B "%windir%\system32\slmgr.vbs" /skms kms.digiboy.ir
    &cscript //B "%windir%\system32\slmgr.vbs" /ato 
    Get-CIMInstance -query "select Name, Description, LicenseStatus from SoftwareLicensingProduct where LicenseStatus=1" | Format-List Name, Description, LicenseStatus
    Start-Sleep -Seconds 4
    $ActivateStatus = (Get-CimInstance -ClassName SoftwareLicensingProduct | Where-Object ApplicationId -EQ 55c92734-d682-4d71-983e-d6ec3f16059f | Where-Object PartialProductKey).LicenseStatus
    If($ActivateStatus -eq 1){
            [Void] [System.Windows.Forms.MessageBox]::Show(
            "System activated successfully.", 
            "11Normalizer", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Asterisk
        )
    }
    Else{
        [Void] [System.Windows.Forms.MessageBox]::Show(
            "Error during activation process.", 
            "11Normalizer", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})

$DisableBG.Add_Click({
    Log("Disabling background applications...")
    Get-ChildItem -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object{
        Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWORD -Value 1
        Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWORD -Value 1
    }
    if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")){
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1
    [Void] [System.Windows.Forms.MessageBox]::Show(
            "Disabled background apps successfully.", 
            "11Normalizer", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Asterisk
    )
})

$DisableCortana.Add_Click({
    Log("Disabling Bing in start menu...")
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
    Log("Stopping and disabling the Windows search indexing service...")
    Stop-Service "WSearch" -WarningAction SilentlyContinue
    Set-Service "WSearch" -StartupType Disabled
    Log("Hiding Search icon on taskbar...")
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    Log("Disabling Cortana...")
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
    Stop-Process -Name SearchApp -Force
    Stop-Process -Name explorer -Force
    [Void] [System.Windows.Forms.MessageBox]::Show(
            "Disabled Cortana successfully.", 
            "11Normalizer", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Asterisk
    )
})

$RemoveBloat.Add_Click({
    Log("Removing bloatware...")
    $BloatList=@(
        "Microsoft.BingNews"
        "Microsoft.BingWeather"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.PowerAutomateDesktop"
        "Microsoft.SecHealthUI"
        "Microsoft.People"
        "Microsoft.Todos"
        "Microsoft.WindowsAlarms"
        "Microsoft.WindowsCamera"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.YourPhone"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"
        "MicrosoftTeams"
    )
    ForEach($BloatApp in $BloatList){
        if((Get-AppxPackage -Name $Bloat).NonRemovable -eq $false){
            Log("Attempting to remove $BloatApp...")
            Try{
                Get-AppxPackage -Name $Bloat | Remove-AppxPackage -ErrorAction Stop | Out-Null
                Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $BloatApp | Remove-AppxProvisionedPackage -Online -ErrorAction Stop
            } Catch{
                Error("Failed to remove $BloatApp due to exception: $($_)")
            }
        }
    }
    [Void] [System.Windows.Forms.MessageBox]::Show(
            "Removed bloatware.", 
            "11Normalizer", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Asterisk
    )
})

$DisableDefender.Add_Click({
    [Void] [System.Windows.Forms.MessageBox]::Show(
            "Feature coming soon", 
            "11Normalizer", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Asterisk
    )
})

[void]$MainForm.ShowDialog()