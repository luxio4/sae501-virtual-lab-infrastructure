# SAE 5.01 – Infrastructure de Salle de TP Virtuelle
**Virtualisation, Active Directory, Automatisation et Supervision**

Ce dépôt présente la conception et le déploiement d’une **infrastructure complète de salle de TP virtualisée**, destinée à héberger des environnements de travail pour des étudiants.  
L’architecture repose sur **Proxmox VE**, une **gestion centralisée des identités via Active Directory**, un **portail web sécurisé** pour la gestion des machines virtuelles, ainsi que des **services avancés de stockage et de supervision**.

---

## Table des matières
1. [Fonctionnalités principales](#fonctionnalités-principales)  
2. [Architecture globale](#architecture-globale)  
3. [Structure du projet](#structure-du-projet)  
4. [Infrastructure de virtualisation](#infrastructure-de-virtualisation)  
5. [Gestion des identités – Active Directory](#gestion-des-identités--active-directory)  
6. [Automatisation des utilisateurs](#automatisation-des-utilisateurs)  
7. [Portail Web de gestion des machines virtuelles](#portail-web-de-gestion-des-machines-virtuelles)  
8. [Services de fichiers et quotas](#services-de-fichiers-et-quotas)  
9. [Supervision et monitoring](#supervision-et-monitoring)  
10. [Sécurité et isolation](#sécurité-et-isolation)  
11. [Green IT / Développement durable](#green-it--développement-durable)  
12. [Documentation](#documentation)  
13. [Licence](#licence)

---

## Fonctionnalités principales

1. **Virtualisation centralisée**
   - Hyperviseur **Proxmox VE (Type 1 – Bare Metal)**
   - Déploiement rapide via templates Windows et Linux
   - Paravirtualisation **VirtIO** pour des performances optimales

2. **Gestion centralisée des identités**
   - **Active Directory (Windows Server 2022)**
   - Authentification unique pour Windows et Linux
   - Groupes de sécurité (PROFS / ELEVES)

3. **Automatisation avancée**
   - Création des utilisateurs via script **PowerShell + CSV**
   - Attribution automatique des droits et des dossiers personnels
   - Synchronisation des pools Proxmox

4. **Portail Web sécurisé**
   - Application **Python / Flask**
   - Gestion des VMs sans accès direct à Proxmox
   - Intégration avec **Apache Guacamole** pour l’accès RDP via navigateur

5. **Stockage sécurisé**
   - Quotas utilisateurs via **FSRM**
   - Isolation stricte des dossiers personnels
   - Access-Based Enumeration (ABE)

6. **Supervision proactive**
   - **Prometheus** pour la collecte des métriques
   - **Grafana** pour la visualisation
   - Surveillance CPU, RAM, disque et services critiques

---

## Architecture globale

L’infrastructure repose sur trois piliers :

- **Virtualisation** : Proxmox VE
- **Identité & Sécurité** : Active Directory
- **Services & Supervision** : Fichiers, quotas, monitoring

### Composants principaux

| Service | Adresse IP | Rôle |
|------|----------|------|
| Proxmox VE | 192.168.1.201 | Hyperviseur |
| Guacamole | 192.168.1.202 | Accès RDP via navigateur |
| Active Directory + Fichiers | 192.168.1.203 | Authentification, DNS, partages |
| Prometheus / Grafana | 192.168.1.204 | Supervision |

---

## Structure du projet

<pre>
   sae501-virtual-lab-infrastructure/
   ├── docs/
   │   ├── Compte_Rendu_SAE501.pdf
   │   └── Guide_Administrateur_Reseau.pdf
   ├── portal/
   │   ├── remiv10.py
   │   ├── requirements.txt
   │   └── guac-portal.service
   ├── scripts/
   │   ├── powershell/
   │   │   └── UserCreator.ps1
   │   └── bash/
   │       └── AutoPoolPerm.sh
   ├── monitoring/
   │   └── prometheus.yml
   ├── README.md
   └── LICENSE
</pre>

## Infrastructure de virtualisation

- **Hyperviseur** : Proxmox VE
- **Réseau** : bridge Linux `vmbr0`
- **Stockage** :
  - `local` : ISO et sauvegardes
  - `local-lvm` : disques VM (LVM Thin Provisioning)
  - `ExStorage` : backups

### Templates
- Windows 10 / 11 :
  - Drivers VirtIO
  - QEMU Guest Agent
  - Généralisation via **Sysprep**
- Ubuntu 22.04 :
  - Intégration AD via **SSSD / Kerberos**

---

## Gestion des identités – Active Directory

- Domaine : `picamal.rt`
- Services :
  - AD DS
  - DNS
- Organisation :
OU=RT
<pre>
   ├── PROFS
   └── ELEVES
</pre>
yaml
Copier le code

### Intégration des postes
- **Windows** : DNS statique, NTP, Kerberos, GPO
- **Linux** : SSSD, realm join, création automatique du home directory

---

## Automatisation des utilisateurs

Provisioning via script **PowerShell** :
- Création des comptes AD
- Affectation aux groupes
- Création des dossiers personnels
- Application des ACL NTFS
- Montage automatique du lecteur Z:

---

## Portail Web de gestion des machines virtuelles

### Technologies
- Python / Flask
- API Proxmox (proxmoxer)
- Apache Guacamole
- MySQL
- Service systemd

### Fonctionnalités
- Authentification unifiée (username@picamal.rt)
- Création de VM (ISO ou template)
- Démarrage / arrêt / suppression
- Pool dédié par utilisateur
- Accès RDP automatique via navigateur

---

## Services de fichiers et quotas

- Serveur de fichiers Windows
- **FSRM** : quotas stricts (2 Go par étudiant)
- **ABE** pour la confidentialité
- Partages :
- `P:` → partage commun
- `Z:` → dossier personnel isolé

---

## Supervision et monitoring

- **Prometheus** : collecte
- **Grafana** : dashboards
- Agents :
- Node Exporter (Linux)
- Windows Exporter (Windows Server)

---

## Sécurité et isolation

- ACL Proxmox strictes
- Pools dédiés par utilisateur
- Suppression de tout accès direct à l’hyperviseur
- Sauvegardes régulières des services critiques

---

## Green IT / Développement durable

- Mutualisation : 30 postes → 1 serveur
- Accès distant via navigateur (clients légers)
- Réemploi de matériel existant
- Réduction de l’empreinte carbone

---

## Documentation

La documentation complète est disponible dans le dossier `docs/` :
- Compte-rendu technique SAE 5.01
- Guide Administrateur Réseau

---

## Licence

Projet académique réalisé dans le cadre du **BUT Réseaux & Télécommunications**.  
Usage pédagogique et démonstratif.
