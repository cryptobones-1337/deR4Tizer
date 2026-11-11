# Listes de domaines du filtrage DNS (phase 7) : sources, licences, choix

État : **prévu**, rien dans le code. Ce document fixe ce que le filtrage par nom de domaine de la phase 7 pourra
télécharger, et pourquoi. Il reprend le dossier de conception de la phase 7 (section 5, recherche documentaire du
2026-10-25).

## Principe

- Le poste téléchargera chaque liste **directement chez sa source**, comme les listes de menaces d'aujourd'hui
  (`menaces.rs` : HTTPS seulement, taille et délai bornés, copie précédente gardée si la nouvelle s'effondre).
  deR4Tizer ne **redistribue** aucune liste.
- Les obligations de partage des licences GPL et CC BY-SA portent sur la redistribution, pas sur l'usage. Une licence
  « non commerciale » restreint en revanche l'**usage**, ce qui exclut les TPE et les communes.
- Ce qui suit est une **lecture technique** des pages des projets, **pas un avis juridique**. Les choix restent au
  mainteneur (décisions D7-2, D7-3 et D7-8 du dossier, ouvertes).
- Les sources seront compilées dans le binaire : aucune adresse de liste ne sera lue d'un fichier.

## Listes examinées

| Liste | Catégorie | Licence ou conditions (d'après la page du projet) | Usage par une TPE | Proposition du dossier |
|---|---|---|---|---|
| EasyPrivacy, EasyList | publicité, pistage | double licence GPLv3 ou CC BY-SA 3.0, au choix ; citer « The EasyList authors » | permis | Par défaut quand « Publicités et pistage » est activé ; règles `||domaine^` sans option seulement ; attribution affichée. |
| AdGuard DNS filter | publicité, pistage | dépôt sous GPL-3.0 ; agrège des listes tierces dont les licences ne sont pas données sur la page | probablement permis, sources amont à vérifier | Alternative si EasyList casse trop de sites. |
| HaGeZi « Multi Light » | publicité, pistage, une partie des logiciels malveillants | GPL-3.0 pour les listes publiées, sans droit sur les données amont d'après le projet | incertain | Alternative, sur décision du mainteneur. |
| HaGeZi « TIF » (Mini) | sécurité | même réserve sur les sources amont | incertain | Seule liste de sécurité gratuite trouvée qui semble utilisable ; sur décision du mainteneur seulement, réserve affichée. |
| URLhaus (abuse.ch) | sécurité | usage commercial soumis à un abonnement payant, d'après les conditions d'abuse.ch | non | Écartée. |
| Phishing Army | sécurité | CC BY-NC 4.0 | non | Reste sous « listes restreintes » pour DNS-001, jamais pour le blocage. |
| ThreatView domaines | sécurité | à vérifier | inconnu | Idem. |
| StevenBlack « unified » | publicité, logiciels malveillants | dépôt sous MIT, mais agrège des listes non commerciales (MVPS, Dan Pollock) | non | Écartée. |
| Résolveur Quad9 (au lieu d'une liste) | sécurité | service gratuit ; conditions à relire par le mainteneur | à confirmer | Proposé comme amont choisi, nommé, pour « Navigation sécurisée ». |

## Ce qui sera bloqué par défaut : rien

Le filtrage sera désactivé à l'installation et après une mise à niveau.

| Activation | Ce qui serait bloqué |
|---|---|
| « Navigation sécurisée » | Domaines des listes de sécurité retenues par le mainteneur, plus le filtrage de l'amont si Quad9 est choisi. Sans liste ni Quad9, l'interface dira « aucune liste de sécurité active : rien n'est bloqué ; les alertes DNS-001 restent ». |
| « Publicités et pistage » | Règles de domaine d'EasyPrivacy et d'EasyList. Jamais groupée avec la sécurité : le risque de casser un site n'est pas le même. |
| Toujours | Rien de la liste de protection compilée, rien de ce que l'utilisateur a autorisé. |
