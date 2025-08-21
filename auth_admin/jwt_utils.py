# jwt_utils.py
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth import get_user_model
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def rotate_refresh_token(refresh_str):
    """
    Génère un nouveau access token à partir d'un refresh token existant.
    Ne stocke plus de blacklist.
    """
    logger.debug(f"[rotate_refresh_token] Début rotation pour refresh token: {refresh_str[:20]}...")

    try:
        refresh = RefreshToken(refresh_str)
        user_id = refresh.get(settings.SIMPLE_JWT.get("USER_ID_CLAIM", "user_id"))
        User = get_user_model()
        user = User.objects.filter(id=user_id, is_active=True).first()
        if not user:
            logger.debug("[rotate_refresh_token] Utilisateur non trouvé ou inactif.")
            return None, None

        # Génère nouveau access token (pas de nouveau refresh)
        new_access = str(refresh.access_token)
        logger.debug(f"[rotate_refresh_token] Nouveau access token généré: {new_access[:20]}...")

        return new_access, str(refresh)

    except TokenError as e:
        logger.debug(f"[rotate_refresh_token] Erreur token: {e}")
        return None, None
    except Exception as e:
        logger.exception(f"[rotate_refresh_token] Exception inattendue: {e}")
        return None, None
