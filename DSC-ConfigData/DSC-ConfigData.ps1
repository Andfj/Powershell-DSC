configuration IISSetup
{
 param(
    [Parameter(Mandatory=$true)] 
	[String[]]$ServerName
 )

 Import-DscResource -ModuleName "PSDesiredStateConfiguration", "xWebAdministration", "cNtfsAccessControl", "xSmbShare"

    node ($ServerName)
    {

#Install pre-requsities

        Package InstallVCRE200832
        {
            Ensure = 'Present'
            Name = "Visual C++ 2008 32bit"
            Path = "C:\TEMP\Microsoft Visual C++ 2008\vcredist_x86.exe"
            Arguments = "/q"
            ProductId = "9BE518E6-ECC6-35A9-88E4-87755C07200F"
        }

        Package InstallVCRE200864
        {
            Ensure = 'Present'
            Name = "Visual C++ 2008 64bit"
            Path = "C:\TEMP\Microsoft Visual C++ 2008\vcredist_x64.exe"
            Arguments = "/q"
            ProductId = "5FCE6D76-F5DC-37AB-B2B8-22AB8CEDB1D4"
        }

        File WindowsLog
        {
            Ensure          = "Present"
            DestinationPath = "C:\Temp\Log"
            Type            = "Directory"
        }


#install windows features
        WindowsFeatureSet WebServer
        {
            Ensure = "Present"
            Name = @("Web-Server", "Web-Mgmt-Console", "Web-IP-Security", "Web-Health")
            IncludeAllSubFeature = $false
        }

#remove default website
        xWebSite  DefaultSite
        {
            Ensure = 'Absent'
            Name = 'Default Web Site'
            PhysicalPath = 'C:\inetpub\wwwroot'
            DependsOn = "[WindowsFeatureSet]WebServer"
        }

#remove default web application pool
        xWebAppPool DefaultAppPool
        {
            Ensure = 'Absent'
            Name = 'DefaultAppPool'
            DependsOn = "[WindowsFeatureSet]WebServer"
        }


#setting logging on all sites
        xIISLogging LogOptions
        {
            LogPath = '%SystemDrive%\inetpub\logs\LogFiles'
            LogFlags = 'Date', 'Time', 'ClientIP', 'UserName', 'ServerIP', 'Method', 'UriStem', 'UriQuery', 'HttpStatus', 'Win32Status', 'BytesSent', 'BytesRecv', 'TimeTaken', 'ServerPort', 'UserAgent', 'Referer', 'HttpSubStatus'
            LogPeriod = 'Daily'
            DependsOn = "[WindowsFeatureSet]WebServer"
        }


#set permissions to c:\websites, C:\Temp\Log folders
$folders = @("C:\WebSites",         "DOMAIN\AppPoolUsers", "Modify"),
           @("C:\Temp\Log",     "DOMAIN\AppPoolUsers", "Modify"),
           @("C:\Temp\Log", "DOMAIN\LogReader",                  "ReadAndExecute")
                
            for($i=0; $i -lt $folders.Length; $i++)
            {
                cNtfsPermissionEntry "WebsitesPermissions$i"
                {
                    Ensure = 'Present'
                    Path = $folders[$i][0]
                    Principal = $folders[$i][1]
                    AccessControlInformation = @(
                        cNtfsAccessControlInformation
                        {
                            AccessControlType = 'Allow'
                            FileSystemRights = $folders[$i][2]
                            Inheritance = 'ThisFolderSubfoldersAndFiles'
                            NoPropagateInherit = $false
                        }
                    )
                    DependsOn = @("[File]DeploymentServiceFolder", "[File]WindowsLog")
                }
            }


#creating Registry keys
$registryValues = @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSSQLServer\Client', 'SharedMemoryOn', '0', 'Dword'),
                  @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo', 'DB1', 'DBMSSOCN,db1.domain.local', 'String'),
                  @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo', 'DB2', 'DBMSSOCN,db2.domain.local', 'String'),
                  @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSSQLServer\Client\SuperSocketNetLib', 'Encrypt', '0', 'Dword'),
                  @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSSQLServer\Client\SuperSocketNetLib', 'ProtocolOrder', 'tcp', 'MultiString'),
                  @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSSQLServer\Client\SuperSocketNetLib\tcp', 'DefaultPort', '1433', 'Dword'),
                  @('HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\MSSQLServer\Client', 'SharedMemoryOn', '0', 'Dword'),
                  @('HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\MSSQLServer\Client\ConnectTo', 'DB1', 'DBMSSOCN,db1.domain.local', 'String'),
                  @('HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\MSSQLServer\Client\ConnectTo', 'DB2', 'DBMSSOCN,db2.domain.local', 'String'),
                  @('HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\MSSQLServer\Client\SuperSocketNetLib', 'Encrypt', '0', 'Dword'),
                  @('HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\MSSQLServer\Client\SuperSocketNetLib', 'ProtocolOrder', 'tcp', 'MultiString'),
                  @('HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\MSSQLServer\Client\SuperSocketNetLib\tcp', 'DefaultPort', '1433', 'Dword')

            for($i=0; $i -lt $registryValues.Length; $i++)
            {
                Registry "UKSQLClient$i"
                {
                    Ensure = 'Present'
                    Key = $registryValues[$i][0]
                    ValueName = $registryValues[$i][1]
                    ValueData = $registryValues[$i][2]
                    ValueType = $registryValues[$i][3]
                
                }
            }

            Registry "UKSQLClientDBlib32"
            {
                Ensure = 'Present'
                Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSSQLServer\Client\DB-Lib'
                ValueName = ''
            }

            Registry "UKSQLClientDBlib64"
            {
                Ensure = 'Present'
                Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\MSSQLServer\Client\DB-Lib'
                ValueName = ''
            }


#creating share for C:\Temp\Log
            xSmbShare AppLogs
            {
                Ensure = 'Present'
                Name = "Application Logs"
                Path = "C:\Temp\Log"
                ReadAccess = "Authenticated Users"
                DependsOn = "[File]WindowsLog"
            }
         
#setup Log Event Destination
            Script logEventDestination
            {
                SetScript = 
                {
                    Write-Verbose "The target resource is not in the desired state"
                    Set-WebConfigurationProperty -Filter "/system.applicationHost/sites/siteDefaults/logFile"  -PSPath 'MACHINE/WEBROOT/APPHOST' -Name logTargetW3C -Value "File,ETW"
                }
                TestScript = 
                {
                    $logDest = Get-WebConfigurationProperty -Filter "/system.applicationHost/sites/siteDefaults/logFile"  -PSPath 'MACHINE/WEBROOT/APPHOST' -Name logTargetW3C
                    return ($logDest -eq "File,ETW")
                }
                GetScript = 
                {
                    return @{ Result = Get-WebConfigurationProperty -Filter "/system.applicationHost/sites/siteDefaults/logFile"  -PSPath 'MACHINE/WEBROOT/APPHOST' -Name logTargetW3C  }
                }

                DependsOn = "[WindowsFeatureSet]WebServer"

            }

#create folders, application pools, websites

        foreach ($Website in $Node.WebSite)
        {
            $folderResourceName = $Website.folder -replace ":", ""

            File $folderResourceName
            {
                Ensure          = "Present"
                DestinationPath = "$($Website.folder)"
                Type            = "Directory"
            }

###########creating credentionals for Application Pool users
            $appPoolUser = $Website.AppUser
            $appPoolPwd = $Website.AppPwd | ConvertTo-SecureString -AsPlainText -Force
            [PSCredential] $appPoolcred = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $appPoolUser, $appPoolPwd

            xWebAppPool $Website.site
            {
                Ensure = "Present"
                Name = "$($Website.site)"
                State = "Started"
                enable32BitAppOnWin64 = $Website.App32bitFlag
                idleTimeout = '00:00:00'
                loadUserProfile = $true

                identityType = 'SpecificUser'
                Credential = $appPoolcred

                logEventOnRecycle = "Time,Requests,Schedule,Memory,IsapiUnhealthy,OnDemand,ConfigChange,PrivateMemory"
                DependsOn = "[WindowsFeatureSet]WebServer"
            }
            

            xWebsite $Website.site
            {
                Ensure = 'Present'
                Name = $Website.site
                State = 'Started'
                PhysicalPath = "$($Website.folder)"
                ApplicationPool = "$($Website.site)"
                BindingInfo = @(
                    foreach ($bindingInfo in $WebSite.bindingInfo)
                    {
                        MSFT_xWebBindingInformation
                        {
                            Protocol              = $bindingInfo.Protocol
                            HostName = $bindingInfo.HostName
                            Port                  = $bindingInfo.Port
                        }
                    }
                )

               DependsOn = @("[File]$folderResourceName","[xWebAppPool]$($Website.site)" )
            }

          }


    }
        
}


IISSetup  -ServerName "ServerName" -ConfigurationData .\ConfigData.psd1  -OutputPath C:\Scripts\DSC-Demo2

Start-DscConfiguration -Wait -Verbose -Path C:\Scripts\DSC-Demo2 -Credential -Force