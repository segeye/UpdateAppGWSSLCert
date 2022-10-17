try
{
    "Logging in to Azure..."
    Connect-AzAccount -Identity
}
catch {
    Write-Error -Message $_.Exception
    throw $_.Exception
}



$Date = Get-Date
$FileTimestamp=$(Get-Date -Date $Date -Format "yyyyMMdd")
$Subscription = "##" #Subscription ID
$VaultName = "##"   #Key Vault name
$Certificate = "##" #Certificate name
$password = "##" #Set password for pfx
$CertName = "##-$($FileTimestamp)" #Name for exported certificate

$cert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $Certificate
$secret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $cert.Name

$secretValueText = '';

Set-AzContext -Subscription $Subscription

#1. Export Cert
#https://learn.microsoft.com/en-us/azure/key-vault/certificates/how-to-export-certificate?tabs=azure-powershell

$ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret.SecretValue)
try {
    $secretValueText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
} finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
}
$secretByte = [Convert]::FromBase64String($secretValueText)
$x509Cert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2($secretByte,'','Exportable,PersistKeySet')
$type = [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx
$pfxFileByte = $x509Cert.Export($type, $password)
[System.IO.File]::WriteAllBytes("$($CertName).pfx", $pfxFileByte)


#2. Import Cert
#https://learn.microsoft.com/en-us/powershell/module/az.network/add-azapplicationgatewaysslcertificate?view=azps-8.3.0
$AppGW = Get-AzApplicationGateway -Name "AppGW1" -ResourceGroupName "Resourcegroupname"
$AppGW = Add-AzApplicationGatewaySslCertificate -ApplicationGateway $AppGW -Name $CertName -CertificateFile "$($CertName).pfx" -Password $password
Set-AzApplicationGateway -ApplicationGateway $AppGw


#3. Update listener
$AppGw = Get-AzApplicationGateway -Name "ApGW1" -ResourceGroupName "Resourcegroupname"
$FEP = Get-AzApplicationGatewayFrontendPort -Name "port_443" -ApplicationGateway $AppGw
$FrontEndIP= Get-AzApplicationGatewayFrontendIPConfig -Name "appGwPublicFrontendIp" -ApplicationGateway $AppGw
$Cert = Get-AzApplicationGatewaySslCertificate -Name $CertName -ApplicationGateway $AppGW
$AppGw = Set-AzApplicationGatewayHttpListener -ApplicationGateway $AppGw -Name "hostname.com_listener" -Protocol "Https" -FrontendIpConfiguration $FrontEndIP -FrontendPort $FEP -SslCertificate $Cert -HostName "hostname.com"
Set-AzApplicationGateway -ApplicationGateway $AppGw

