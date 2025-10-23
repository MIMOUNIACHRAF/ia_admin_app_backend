qa_data = [
    ("Comment puis-je m'inscrire sur la plateforme ?", 
     "Cliquez sur le bouton 'S'inscrire' en haut de la page et remplissez le formulaire d'inscription."),
    ("Quels postes sont ouverts actuellement ?", 
     "Consultez notre site carrière pour la liste complète des postes disponibles."),
    ("Puis-je modifier mes informations après inscription ?", 
     "Oui, vous pouvez modifier vos informations personnelles depuis votre profil à tout moment."),
    ("Comment postuler à une offre disponible ?", 
     "Connectez-vous à votre compte, accédez à la section 'Offres' et cliquez sur 'Postuler'."),
    ("Dois-je créer un compte pour postuler ?", 
     "Oui, un compte candidat est nécessaire pour suivre vos candidatures et mises à jour."),
    ("Est-ce que l'inscription est gratuite ?", 
     "Oui, l'inscription sur la plateforme est totalement gratuite pour tous les utilisateurs."),
    ("Comment supprimer mon compte ?", 
     "Vous pouvez supprimer votre compte depuis les paramètres de votre profil, section 'Confidentialité'."),
    ("Que faire si je ne reçois pas l'email de confirmation ?", 
     "Vérifiez votre dossier spam ou contactez le support technique via le formulaire de contact."),
    ("Puis-je contacter directement un recruteur ?", 
     "Oui, une fois que votre candidature est acceptée, vous pouvez échanger avec le recruteur via le chat intégré."),
    ("Quels navigateurs sont compatibles avec la plateforme ?", 
     "La plateforme fonctionne sur Chrome, Firefox, Edge et Safari dans leurs versions récentes."),
    ("Comment changer la langue de l'interface ?", 
     "Allez dans vos paramètres de profil et sélectionnez la langue souhaitée dans la section 'Langue'."),
    ("Comment contacter le support technique ?", 
     "Utilisez le formulaire de contact disponible dans le menu 'Aide' ou envoyez un email à support@example.com")
]

# Transformation en JSON avec ordre
json_list = [{"question": q, "reponse": r, "ordre": i+1} for i, (q, r) in enumerate(qa_data)]

import json
json_output = json.dumps(json_list, ensure_ascii=False, indent=4)
print(json_output)
