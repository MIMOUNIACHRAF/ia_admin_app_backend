# Backend Django pour l'Application IA Admin

Ce projet est le backend Django pour l'application IA Admin, configuré pour être déployé sur Render et communiquer avec un frontend React.

## Configuration CORS

La configuration CORS a été optimisée pour permettre une communication fluide entre le frontend React et le backend Django:

- Le middleware `corsheaders.middleware.CorsMiddleware` est positionné juste après `SecurityMiddleware`
- `CORS_ALLOWED_ORIGINS` inclut toutes les URLs frontend nécessaires
- En mode DEBUG, `CORS_ALLOW_ALL_ORIGINS` est activé pour faciliter le développement
- Configuration complète des méthodes HTTP, en-têtes autorisés et en-têtes exposés

## Variables d'Environnement

Le projet utilise les variables d'environnement suivantes (définies dans le fichier `.env`):

```
SECRET_KEY=votre-clé-secrète
DEBUG=True  # Mettre à False en production
ALLOWED_HOSTS=localhost,127.0.0.1,votre-domaine.com
CORS_ALLOWED_ORIGINS=http://localhost:5174,https://votre-frontend.com
```

## Déploiement sur Render

Le projet est configuré pour être déployé sur Render avec:

- Un `Procfile` qui spécifie la commande de démarrage: `web: gunicorn ia_admin_app_backend.wsgi:application`
- `requirements.txt` incluant tous les packages nécessaires
- Configuration de Whitenoise pour servir les fichiers statiques

### Étapes de Déploiement

1. Assurez-vous que votre code est à jour sur GitHub
2. Configurez un nouveau service Web sur Render
3. Connectez votre dépôt GitHub
4. Définissez les variables d'environnement sur Render
5. Déployez l'application

## Développement Local

### Installation

```bash
# Cloner le dépôt
git clone <url-du-dépôt>
cd ia_admin_app_backend

# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt

# Appliquer les migrations
python manage.py migrate

# Créer un superutilisateur
python manage.py create_admin
```

### Lancement du Serveur

```bash
python manage.py runserver
```

Le serveur sera accessible à l'adresse http://localhost:8000/

### Après Modification de la Configuration CORS

Après toute modification de la configuration CORS:

1. Redémarrez le serveur Django
2. Nettoyez le cache du navigateur (Ctrl+Shift+R)
3. Vérifiez les en-têtes CORS dans les DevTools du navigateur

## Documentation Supplémentaire

Pour plus de détails sur la configuration et l'utilisation du projet, consultez:

- [Guide de Configuration CORS](cors_configuration_guide.md)
- [Modifications Recommandées pour CORS](cors_modifications_recommandees.md)
- [Plan de Déploiement](deployment_plan.md)

## Procédure Git Pull/Push

Pour éviter les conflits de migrations:

1. Avant de commencer à travailler: `git pull origin main`
2. Vérifier les migrations: `python manage.py showmigrations`
3. Appliquer les migrations si nécessaire: `python manage.py migrate`
4. Après modifications, tester localement
5. Pousser les changements: `git add . && git commit -m "Description" && git push origin main`
