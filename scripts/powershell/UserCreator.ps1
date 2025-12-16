# -----------------------------------------------------------
# Script : Import CSV + Création utilisateurs AD + HomeFolder + Ajout groupe
# -----------------------------------------------------------

$OU = "OU=RT,DC=picamal,DC=rt"            # OU exacte
$Server = "WIN-Q3SF32B10EK"                         # nom de serveur (hostname)
$HomeShare = "Partage_Perso$"                       # Nom du partage caché
$DriveLetter = "Z:"                                 # Lettre du lecteur
$DefaultPassword = "mdp*"                      # MDP initial
$CSV = "C:\scripts\user.csv"                 # Chemin fichier CSV

# Nomsgroupes DANS L'AD
$GroupProf = "PROFS"
$GroupEleve = "ELEVES"

# -----------------------------------------------------------

# Conversion du mot de passe en chaîne sécurisée
$SecurePassword = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force

# -----------------------------------------------------------
function Create-User {
    param(
        [Parameter(Mandatory=$true)] [string]$SamAccountName,
        [Parameter(Mandatory=$true)] [string]$GivenName,
        [Parameter(Mandatory=$true)] [string]$Surname,
        [Parameter(Mandatory=$true)] [string]$Group
    )

    $DisplayName = "$GivenName $Surname"
    # Adapter le domaine ci-dessous (picamal.rt selon tes screens précédents)
    $UserPrincipalName = "$SamAccountName@picamal.rt" 
    $HomePath = "\\$Server\$HomeShare\$SamAccountName"

    # --- 1. Création de l'utilisateur AD ---
    Try {
        # On vérifie d'abord si l'utilisateur existe pour éviter une erreur
        if (Get-ADUser -Filter {SamAccountName -eq $SamAccountName} -ErrorAction SilentlyContinue) {
            Write-Host "[-] L'utilisateur $SamAccountName existe déjà." -ForegroundColor Yellow
        }
        else {
            New-ADUser `
                -SamAccountName $SamAccountName `
                -GivenName $GivenName `
                -Surname $Surname `
                -Name $DisplayName `
                -DisplayName $DisplayName `
                -UserPrincipalName $UserPrincipalName `
                -AccountPassword $SecurePassword `
                -Enabled $true `
                -Path $OU `
                -HomeDirectory $HomePath `
                -HomeDrive $DriveLetter `
                -ErrorAction Stop

            Write-Host "[+] Utilisateur AD créé : $SamAccountName" -ForegroundColor Cyan
        }
    }
    Catch {
        Write-Host "[!] Erreur création AD pour $SamAccountName : $_" -ForegroundColor Red
        return # On arrête si l'AD échoue
    }

    # --- Création du dossier personnel
    if (-not (Test-Path $HomePath)) {
        Try {
            New-Item -ItemType Directory -Path $HomePath -Force | Out-Null
            Write-Host "    [+] Dossier créé : $HomePath" -ForegroundColor Gray
        }
        Catch {
            Write-Host "    [!] Erreur création dossier : $_" -ForegroundColor Red
            return
        }
    }

    # --- Permissions ACL sur le dossier perso
    Try {
        $acl = Get-Acl $HomePath
        
        # Règle : Utilisateur = Modify (Modification)
        # ContainerInherit,ObjectInherit = S'applique aux sous-dossiers et fichiers
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $SamAccountName,
            "Modify", 
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        
        $acl.SetAccessRule($rule)
        Set-Acl -Path $HomePath -AclObject $acl -ErrorAction Stop
        Write-Host "    [+] Permissions NTFS appliquées." -ForegroundColor Gray
    }
    Catch {
        Write-Host "    [!] Erreur permissions NTFS : $_" -ForegroundColor Red
    }

    # --- Assignation groupe pour chaque user
    Try {
        #le switch insensible à la casse par défaut en PowerShell
        switch ($Group) {
            "PROFS"  { Add-ADGroupMember -Identity $GroupProf -Members $SamAccountName -ErrorAction Stop }
            "ELEVES" { Add-ADGroupMember -Identity $GroupEleve -Members $SamAccountName -ErrorAction Stop }
            
            # Gestion d'erreur si le CSV contient autre chose
            default  { Write-Host "    [?] Groupe inconnu dans le CSV : $Group" -ForegroundColor Magenta }
        }
        Write-Host "    [+] Ajouté au groupe $Group." -ForegroundColor Green
    }
    Catch {
        if ($_.Exception.Message -like "*déjà membre*") {
            Write-Host "    [-] Déjà membre du groupe." -ForegroundColor Yellow
        } else {
            Write-Host "    [!] Erreur ajout groupe : $_" -ForegroundColor Red
        }
    }
    
    Write-Host "---------------------------------------------------"
}


# --- TRAITEMENT du CSV

# Vérification présence fichier
if (-not (Test-Path $CSV)) {
    Write-Host "ERREUR FATALE : Le fichier CSV est introuvable : $CSV" -ForegroundColor Red
    exit
}

# Importation du csv
$Users = Import-Csv -Path $CSV -Delimiter ";" 

foreach ($u in $Users) {
    # On appelle la fonction pour chaque ligne
    Create-User `
        -SamAccountName $u.SamAccountName `
        -GivenName $u.GivenName `
        -Surname $u.Surname `
        -Group $u.Group
}

Write-Host "Opération terminée !" -ForegroundColor Green

