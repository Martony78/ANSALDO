<#	
	.NOTES
	===========================================================================
	 Created on:   	15/11/2016 10:04
	 Created by:   	Mathieu Ait Azzouzene
	 Organization: 	Experteam Corp
	 Filename:		Rollback_PSAUME.ps1
	===========================================================================
	.DESCRIPTION
		This script reverts configuration made by Update_PSAUME.ps1 to RATP PSAUME
		Workstations running on Windows XP. 
#>

$ScriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$Name = 'Rollback PSAUME Workstations'
$ExecutionDate = (Get-Date -UFormat "%Y-%m-%d %Hh%M").ToString()
$TempPath = "$env:Windir" + '\Temp\' + "$Name"
$Logfile = "$Name" + " $ExecutionDate" + '.log'
$OS = Get-WmiObject -class Win32_OperatingSystem
$OSServicePack = 'SP' + (Get-WmiObject -class Win32_OperatingSystem).ServicePackMajorVersion
$Lang = (Get-Culture).Name
$InstalledPatches = (Get-HotFix | Select-Object HotfixID)
$TCPPorts = 135,139,445,3389
$UDPPorts = 123,445,138,137
$DefaultUser = "$env:SystemDrive\Documents and Settings\Default User"
$UserProfiles = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'
$GUIDs = Get-ChildItem -Path $UserProfiles |	Where-Object {$_.PSChildName -like 'S-1-5-21-*'} | Select-Object -expand 'PSChildName'

$ErrorActionPreference = 'Continue'

<#	
	===========================================================================

							Déclaration des Fonctions
					
	===========================================================================
#>

############################################################################################
#                                                                                          #
#	Détermine et créé le chemin du fichier de logs s'il n'existe pas.					   #
#                                                                                          #
############################################################################################

Function Write-Log
{ 
	<#
	.Synopsis 
	   Write-Log -Path "$TempPath\$LogFile" Ecris dans le fichier de logs en y ajoutant le time stamp.
	.DESCRIPTION 
	   La fonction Write-Log permet d'écrire dans un fichier de journal. 
	.NOTES 
	   Created by: Mathieu Aït Azzouzene
	.PARAMETER Message 
	   Message est le contenu à écrire dans le fichier de logs.  
	.PARAMETER Path 
	   Le chemin du fichier de journal, si il n'existe pas il est créé.  
	.PARAMETER Level 
	   Spécifie la criticité du message (i.e. Error, Warning, Informational) 
	.PARAMETER NoClobber 
	   Option permettant de ne pas écraser un fichier existant. 
	.EXAMPLE 
	   Write-Log -Path "C:Temp\log.log" -Message 'Log message'  
	   Ecrit le message "Log message" dans le fichier "C:Temp\log.log". 
	.EXAMPLE 
	   Write-Log -Message 'Folder does not exist.' -Path c:\Logs\Script.log -Level Error 
	   Ecrit le message en tant que message d'erreur. 
	#>
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("LogContent")] 
        [string]$Message, 
 
        [Parameter(Mandatory=$false)] 
        [Alias('LogPath')] 
        [string]$Path = "$TempPath\$LogFile", 
         
        [Parameter(Mandatory=$false)] 
        [ValidateSet("Error","Warn","Info")] 
        [string]$Level="Info"
    ) 
 
    Begin {} 
	
    Process 
    { 
        # Création du chemin du fichier s'il n'existe pas. 
        If (!(Test-Path $Path))
			{ 
            $NewLogFile = New-Item $Path -Force -ItemType File 
            } 
 
        # Format Date
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
 
        # Ajoute ERROR ou WARNING au message en fonction de l'option de criticité. 
        switch ($Level) { 
            'Error' { 
                $LevelText = 'ERROR:' 
                } 
            'Warn' { 
                $LevelText = 'WARNING:' 
                } 
            'Info' { 
                $LevelText = ''
                } 
            } 
         
        # Ajoute l'entrée à $Path 
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append -Encoding UTF8
    } 
    End {} 
}

#Fonction testant l'existence d'une valeur du registre.
Function Test-RegistryValue
{
PARAM
	(
	[parameter(Mandatory=$True)]
	[ValidateNotNullOrEmpty()]$Path,

	[parameter(Mandatory=$True)]
	[ValidateNotNullOrEmpty()]$Value
	)
	
Clear-Variable RegValue -ErrorAction SilentlyContinue
$RegValue = Get-ItemProperty -Path $Path $Value -ErrorAction SilentlyContinue
If ($RegValue)
	{
	Return $RegValue.$Value
	}
Else
	{
	Return $null
	}
}

Function Set-RegistryValue
{
PARAM
	(
	[string]$KeyPath,
	[string]$ValueName,
	[string]$OldValue,
	[string]$NewValue,
	[ValidateSet('String','ExpandString','Binary','DWord','MultiString','Qword','Unknown')]
	[string]$ValueType
	)

$OldValue = (Test-RegistryValue -Path $KeyPath -Value $ValueName)
	
If ($OldValue)
	{
    Write-Log -Message "Registry value '$ValueName' exists under '$KeyPath' and is equal to '$OldValue'" -Level Warn
    Try
        {    
		$UpdateKey = Set-ItemProperty "$KeyPath" -Name $ValueName -Value $NewValue –ErrorVariable UpdateKeyError
		Write-Log -Message "Registry value '$ValueName' successfully updated under '$KeyPath', new value is '$NewValue'" 
		}
        Catch
		{
        Write-Log -Message " An error occured while updating '$ValueName' under '$KeyPath', details :" -Level ERROR
		Write-Log -Message "$_" -Level ERROR
		Return $UpdateKeyError
        } 
    }
Else
    {
    Write-Log -Message "Creating registry value '$ValueName' under '$KeyPath'..." 
    If (!(Test-Path "$KeyPath"))
		{
		Write-Log -Message "Registry key '$KeyPath' does not exist, creating it." 
		Try
            {
            $Create = New-Item -Path "$KeyPath" –ErrorVariable CreateKeyError
			Write-Log -Message "Registry key '$KeyPath' successfully created" 
            }
        Catch
            {
            Write-Log -Message "An error occured while creating '$KeyPath', details:" -Level ERROR
			Write-Log -Message "$_" -Level ERROR
			Return $CreateKeyError
            }
		}
		
    Try
        {
			If ($ValueType -eq "Binary")
			{
				$hexified = $NewValue.Split(',') | % { "0x$_"}
				$SetValue = New-ItemProperty "$KeyPath" -Name $ValueName -Value ([byte[]]$hexified) -PropertyType $ValueType –ErrorVariable SetValueError 
			}
			Else
			{
	        	$SetValue = New-ItemProperty "$KeyPath" -Name $ValueName -Value $NewValue -PropertyType $ValueType –ErrorVariable SetValueError
			}
	        Write-Log -Message "Registry value '$ValueName' successfully created under '$KeyPath' containing '$NewValue'" 
	    }
    Catch
        {
        Write-Log -Message " An error occured while creating '$ValueName' under '$KeyPath', details:" -Level ERROR
		Write-Log -Message "$_" -Level ERROR
		Return $SetValueError
        }
    }    
}

Function Invoke-Process
{
	PARAM
	(
		$ProcessFile,
		$Arguments
	)
	
	Begin {}
	
	Process
	{
		Clear-Variable -Name 'Setup' -ErrorAction SilentlyContinue
		If ($Arguments -eq $null)
		{
			$Setup = (Start-Process -FilePath "$ProcessFile" -Wait -PassThru)
		}
		Else
		{
			$Setup = (Start-Process -FilePath "$ProcessFile" -ArgumentList "$Arguments" -Wait -PassThru)
		}
		If ($Setup.ExitCode -eq 0)
		{
			Write-Log -Message "$ProcessFile has been executed without error."
		}
		ElseIf ($Setup.ExitCode -eq 3010)
		{
			Write-Log -Message "$ProcessFile has been successfully executed but a reboot is required." -Level WARNING
		}
		Else
		{
			Write-Log -Message "An error occured while executing $ProcessFile. Error Code : '$($Setup.ExitCode)'" -Level ERROR
		}
		Return $Setup.ExitCode
	}
	
	End {}
}
<#	
	===========================================================================

							Exécution du script
					
	===========================================================================
#>

Write-Log "Démarrage de '$Name'..."

#Getting Operating System Architecture:
If ($env:PROCESSOR_ARCHITEW6432)
{
    $Arch = 'x64'
}
ElseIf ($env:PROCESSOR_ARCHITECTURE -eq 'amd64')
{
    $Arch = 'x64'
}
ElseIf ($env:PROCESSOR_ARCHITECTURE -eq 'x86')
{
    $Arch = 'x86'
}
Else
{
    Write-Log -Message 'The computer Operating System architecture is not compatible with this script...exiting.' -Level Error
    Exit 1
}
Write-Log -Message "Operating System architecture is '$Arch'"

Write-Log "NOM ORDINATEUR = '$Env:ComputerName'"

Write-Log "OS = '$($OS.Caption)'"

Write-Log "SERVICE PACK = '$OSServicePack'"

#Conversion du numéro de version.
		    Switch (($OS.Version).Substring(0,3)) 
			{
		        "5.1" { $WIN = "XP" }
		        "5.2" { $WIN = "2003" }
		        "6.1" { If ($os.ProductType -eq 1) { $WIN = "W7" } Else { Write-Log -Path "$TempPath\$LogFile" 'Operating System not supported, exiting' -Level ERROR; Exit 1 } }
				Default { Write-Log -Path "$TempPath\$LogFile" 'Operating System not supported, exiting' -Level ERROR; Exit 1 }
			}

Write-Log -Path "$TempPath\$LogFile" 'Enabling Autoplay.'
Set-RegistryValue -KeyPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ValueName 'NoDriveTypeAutoRun' -NewValue '0x00000091' -ValueType DWord

Write-Log -Path "$TempPath\$LogFile" 'Enabling Administrative Shares.'
Set-RegistryValue -KeyPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -ValueName 'AutoShareServer' -NewValue '0x00000001' -ValueType DWord
Set-RegistryValue -KeyPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters' -ValueName 'AutoShareWks' -NewValue '0x00000001' -ValueType DWord

Write-Log -Path "$TempPath\$LogFile" 'Enabling Windows Hotkeys.'
Set-RegistryValue -KeyPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ValueName 'NoWinKeys' -NewValue '0x00000000' -ValueType DWord
if ((Get-Service remoteregistry).status -eq 'stopped')
{
	Write-Log -Path "$TempPath\$LogFile" 'Enabling Remote Registry Service.'
	set-service remoteregistry -startuptype automatic
	Write-Log -Path "$TempPath\$LogFile" 'Remote Registry Service is stopped, starting it.'
	Start-Service remoteregistry
}

Write-Log -Path "$TempPath\$LogFile" "Unblocking Ports..."
Start-Process -FilePath "$ScriptPath\IPSeccmd.exe" -ArgumentList '-w REG -p "ANSALDO Port Filtering Policy" -o' -Wait -PassThru

Write-Log -Path "$TempPath\$LogFile" 'Reinstalling Optionnal components.'
Start-Process -FilePath sysocmgr -ArgumentList "/i:$env:windir\inf\sysoc.inf /u:`"$ScriptPath\componentsRollback.txt`"" -Wait -Passthru

Start-Process -FilePath RunDll32 -ArgumentList "advpack.dll, LaunchINFSection $env:windir\inf\msnetmtg.inf,NetMtg.Install" -Wait -Passthru

Write-Log -Path "$TempPath\$LogFile" 'Enabling USB Storage Devices.'
Set-RegistryValue -KeyPath 'HKLM:\SYSTEM\CurrentControlSet\services\USBSTOR' -ValueName 'Start' -NewValue '0x00000003' -ValueType Dword
Start-Process 'icacls' -ArgumentList "$env:windir\inf\usbstor.inf /Deny `"Everyone`":(f)" -Wait
Start-Process 'icacls' -ArgumentList "$env:windir\inf\usbstor.pnf /Deny `"Everyone`":(f)" -Wait

Write-Log -Path "$TempPath\$LogFile" 'Disabling Windows Key.'
Set-RegistryValue -KeyPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layout' -ValueName 'Scancode Map' -NewValue "00,00,00,00,00,00,00,00,03,00,00,00,00,00,5b,e0,00,00,5c,e0,00,00,00,00" -ValueType Binary
#Affichage d'un Pop-Up de fin d'exécution
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
[System.Windows.Forms.MessageBox]::Show('Installation Terminée, Appuyez sur OK pour redémarrer.', 'Update PSAUME', 'ok', 'Information') | Out-Null

Write-Log -Message 'Script execution ended.'

Restart-Computer

Exit