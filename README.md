# GROUPE SABA SÉCURITÉ — Application Web

Application de suivi des sites et des visites avec validation et rapports, en français. Tous les sites sont pris en charge sans limitation à la Zone A.

## Fonctionnalités
- Identification par mot de passe haché et six rôles (administrateur, coordinateur général, responsable sécurité, DGA, contrôleur, consultation).
- Création libre de zones, modification de leur nom et responsable, affectation et transfert des sites entre zones.
- Répertoire des sites (ajout, modification, recherche, import CSV).
- Déclaration des visites et suivi des statuts EN ATTENTE, VALIDÉE, REJETÉE.
- Validation par **un seul** des trois responsables habilités : coordinateur général, responsable sécurité ou DGA.
- Tous les trois peuvent consulter chaque rapport et répondre aux conversations, y compris après validation. Les visiteurs répondent depuis leur rapport.
- Tableau de bord annuel, rapports par dates et export CSV lisible par Excel.
- Base SQLite persistante, journal d'audit interne, protection CSRF.
- **Notifications intégrées** (cloche avec compteur actualisé automatiquement toutes les 20 secondes) pour nouveaux rapports, réponses, validations, rejets et annulations.
- **Annulation d'une validation** par un coordinateur général, responsable sécurité ou DGA, motif obligatoire, remise EN ATTENTE, journalisation et possibilité de revalider.

## Exécution locale
Python 3.12 recommandé.

```bash
pip install -r requirements.txt
# Linux/macOS
export SECRET_KEY="une_longue_cle_aleatoire"
export SETUP_KEY="un_code_installation_confidentiel"
python app.py
```

Sur Windows PowerShell :
```powershell
$env:SECRET_KEY="une_longue_cle_aleatoire"
$env:SETUP_KEY="un_code_installation_confidentiel"
python app.py
```

Ouvrir http://127.0.0.1:5000/setup, saisir le code SETUP_KEY et créer le compte administrateur. Les autres comptes sont créés via « Utilisateurs ».

## Déploiement Render
1. Décompresser ce ZIP et déposer son contenu à la racine d'un dépôt GitHub privé.
2. Dans Render, choisir « New » → « Blueprint » et sélectionner le dépôt ; `render.yaml` configure le service et son disque permanent. Un service payant avec disque persistant est nécessaire pour cette configuration SQLite.
3. Après déploiement, retrouver la valeur **SETUP_KEY** dans les variables d'environnement du service Render (ne pas la divulguer). Ouvrir `https://VOTRE-APP.onrender.com/setup` pour créer votre compte administrateur.
4. Ajouter les autres utilisateurs via l'interface. Sauvegarder régulièrement le fichier de base de données et privilégier une base PostgreSQL gérée pour une exploitation à grande échelle.

### Import du fichier Excel
Dans Excel, ouvrir la feuille contenant les sites, puis « Enregistrer sous » → CSV UTF-8. Préparer les en-têtes `code;nom;quartier;responsable;client;situation;observations` (seuls `code` et `nom` sont obligatoires). L'import CSV se trouve dans le menu « Import ».

### Périmètre de cette première version
Cette version reprend les **principales fonctions** connues du suivi des visites. Elle ne prétend pas reproduire exactement la présentation ou toutes les formules du fichier `GROUPE_SABA_SECURITE_Suivi_Visites_ZONE A.xlsx`, qui n'était pas accessible en tant que fichier source lors de la génération. L'import de sites est au format CSV ; l'import direct `.xlsx`, les pièces jointes/photos, les notifications par e-mail/SMS/push externe et les rapports PDF ne sont pas intégrés (les notifications internes à l'application sont opérationnelles).

### Sécurité et exploitation
Ne jamais publier les variables secrètes. Utiliser HTTPS en production, changer les mots de passe initiaux, limiter les accès administrateurs et conserver des sauvegardes hors du service. Le serveur de développement Flask n'est pas adapté à la production ; Render utilise Gunicorn.

### Ajouts de cette version
Créer les zones depuis **Zones**, affecter les sites depuis **Sites**, puis ouvrir une visite depuis **Visites & validations** pour consulter son rapport et échanger. Les décisions enregistrées sont conservées pendant les échanges ultérieurs.

## Mise à jour depuis une version déjà déployée

1. **Faire une sauvegarde de la base de données du disque persistant Render** (`/var/data/saba.sqlite3`) avant le déploiement. Conserver le service et le disque actuels.
2. Dans le dépôt GitHub actuellement lié au service Render, **remplacer les fichiers du code** avec ceux du ZIP (ne pas créer un nouveau service Render ni supprimer le disque).
3. Confirmer que `DATABASE_PATH=/var/data/saba.sqlite3` et que le disque Render existant est monté sur `/var/data`. La mise à jour SQLite est **additive** : la table `notifications` et ses index sont créés au démarrage sans supprimer les visites, messages ou utilisateurs.
4. Une fois Render redéployé, ouvrir l'application : le lien **🔔 Notifications** apparaît dans le menu. Les nouvelles notifications sont créées à compter de cette version, sans génération artificielle pour les anciennes visites.
5. Ouvrir une visite **VALIDÉE** avec un compte coordinateur général / responsable sécurité / DGA pour voir **Annuler la validation**. Après saisie du motif, la visite passe **EN ATTENTE** et peut être validée à nouveau. L'historique reste consultable sur la fiche.

**Important :** le fichier ZIP ne contient pas les données de la base de production. Ne pas repartir d'un nouveau service ni écraser la base existante.

## Mise à jour — Effectifs, suppression de sites et récupération des mots de passe (19/11/2026)

### Effectifs par site
- Connectez-vous avec le compte **Administrateur**, **Coordinateur général**, **Responsable sécurité** ou **DGA** ; dans **Sites**, saisissez le nombre d’agents affectés à chaque site puis cliquez sur **Enregistrer**. Les **Contrôleurs** et les utilisateurs en **Consultation** voient les effectifs sans pouvoir les modifier.
- Le nombre d'agents apparaît dans le répertoire, avec le nom/date du dernier auteur ; le changement est consigné dans le journal d'audit. Un nombre `0` est valide et différent de « non renseigné ».
- Le tableau de bord présente la somme des effectifs des sites **ACTIFS** non archivés ainsi que le nombre de sites sans effectif renseigné.
- Les rapports et exports CSV montrent le **dernier effectif actuel du site** et non une valeur historique par visite.

### Supprimer, restaurer et effacer un site
- Seul le rôle **Administrateur** peut utiliser l'action **Supprimer**. Il doit indiquer un motif puis confirmer.
- La suppression normale **archive** le site : il disparaît des sites disponibles pour de nouvelles visites mais ses visites, conversations et validations restent disponibles dans les rapports et les historiques.
- Dans **Sites → Voir les sites supprimés**, l'administrateur peut le restaurer.
- L'action **Effacer définitivement** n'apparaît que sur un site archivé **sans visite liée**. Elle est irréversible. Une sauvegarde préalable reste conseillée.

### Mot de passe oublié
- À la connexion, cliquez sur **Mot de passe oublié ?** pour connaître la procédure.
- L'administrateur va dans **Utilisateurs**, clique sur **Réinitialiser le mot de passe** pour un collègue, puis transmet discrètement le mot de passe provisoire affiché **une seule fois**.
- L'utilisateur se connecte avec ce code et est **obligé de définir un nouveau mot de passe** d'au moins 12 caractères avant de continuer à travailler.
- Les anciens mots de passe ne sont jamais affichés (ils sont enregistrés sous forme de hachage).
- **Pour l'administrateur lui-même**, une récupération de secours est disponible uniquement si `ADMIN_RECOVERY_KEY` a été préalablement renseigné dans les variables d'environnement Render, avec une clé aléatoire distincte d'au moins 32 caractères. Générer la clé sur un poste sûr, par exemple `python -c "import secrets; print(secrets.token_urlsafe(40))"`, puis la stocker dans Render et dans un coffre-fort de mots de passe. Le formulaire **Mot de passe oublié ? → Utiliser la clé de secours** permet ensuite de remplacer le mot de passe d'un compte administrateur avec cette clé. Sans cette configuration, demander à un autre administrateur habilité de réinitialiser le compte.

### Déployer la nouvelle version sans perdre les données
1. **Sauvegarder** la base de production avant toute opération (`/var/data/saba.sqlite3` sur le disque persistant Render) et conserver le service actuel.
2. Décompresser ce ZIP et mettre à jour les **fichiers de code** du même dépôt GitHub ; ne pas mettre de base `.sqlite3` dans GitHub.
3. Conserver le disque Render actuel et la même valeur de `DATABASE_PATH`; laisser Render redéployer le code.
4. La migration de base au lancement ajoute les colonnes d'effectifs, d'archivage et de réinitialisation des comptes. Elle ne remplace pas les sites, visites ou utilisateurs existants.
5. Tester avec un compte administrateur et chacun des trois validateurs (modification autorisée), puis avec un compte contrôleur et consultation (modification refusée), avant une utilisation générale. Vérifier également qu'un site archivé reste présent dans les anciens rapports.

**Important :** l'archive ZIP fournit les fichiers de l'application, **pas** une modification directe de votre déploiement Render. Il faut mettre le code à jour pour voir les nouvelles fonctions sur le site en ligne. En l'absence de configuration d'envoi e-mail, le mot de passe oublié passe par l'administrateur ; aucun mot de passe n'est envoyé automatiquement par e-mail ou SMS.


## Précision des droits — effectifs par site
- **Gestion des effectifs** (saisie et modification) réservée à l’administrateur et aux trois validateurs : coordinateur général, responsable sécurité et DGA.
- Les contrôleurs et le rôle consultation **ne peuvent pas modifier les effectifs**, y compris en accédant directement à l’URL de mise à jour (réponse HTTP 403).
- La lecture des effectifs reste accessible aux utilisateurs authentifiés.
- Aucune modification de la base de données n’est nécessaire pour ce changement de droits.
