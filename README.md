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
