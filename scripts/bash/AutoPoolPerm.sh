#!/bin/bash

REALM="picamal.rt"       # Nom du realm
GROUPS="ELEVES PROFS"    # Groupe AD affecter par le script
ROLE="UserVMAdminPool"   # A potentiellement changer

# Met à jour les utilisateur depuis l'ad
pveum realm sync $REALM --scope both --remove-vanished "acl, properties, entries"

# Liste les utilisateurs
users=$(pveum user list | awk -v realm="$REALM" '$2 ~ "@"realm"$" {print $2}')

for user in $users; do
    # Au lieu de juste prendre l'uid, on transforme 'user@realm.ext' en 'user-realm-ext'
    # On remplace le '@' et les '.' par des tirets '-'
    pool_name=$(echo "$user" | sed 's/[@.]/-/g')

    # Vérifier si user appartient déjà à un des groupes cibles
    in_group=0
    for grp in $GROUPS; do
        if pveum user list | grep -A4 "$user" | grep -q "$grp"; then
            in_group=1
            break
        fi
    done

    # Si non membre : on ignore
    if [ $in_group -eq 0 ]; then
        continue
    fi

    # Créer pool si manquante (Vérification avec le nouveau nom pool_name)
    if ! pvesh get /pools | grep -q "\"poolid\" : \"$pool_name\""; then
        echo "[INFO] Creating pool $pool_name for $user"
        pvesh create /pools --poolid "$pool_name"
    fi

    # Assigner permissions si absentes (Sur le chemin du nouveau pool)
    if ! pvesh get /access/acl | grep -q "\"path\" : \"/pool/$pool_name\""; then
        echo "[INFO] Assigning permissions for $user on $pool_name"
        pvesh set /access/acl --path "/pool/$pool_name" --users "$user" --roles "$ROLE"
    fi
done