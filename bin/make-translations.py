#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Builds the fr_CA and fr_FR .po files for translate.wordpress.org.

Usage: bin/make-translations.py STABLE_TEMPLATE.po README_TEMPLATE.po OUT_DIR

The templates are the "untranslated" exports of the Stable and Stable Readme
projects on translate.wordpress.org, so that msgids match exactly what
GlotPress extracted. Translations below are written once in Canadian French;
fr_FR differences come from tokens and typography (non-breaking space before
; ? ! in addition to : and inside guillemets).
"""

import re
import sys
from datetime import datetime, timezone

NBSP = ' '

TOKENS = {
    'fr_CA': {'{adresses_courriel}': 'adresses de courriel', '{de_jumelage}': 'de jumelage', '{jumelage}': 'jumelage'},
    'fr_FR': {'{adresses_courriel}': 'adresses e-mail', '{de_jumelage}': 'd’appairage', '{jumelage}': 'appairage'},
}

# Interface strings, in the order of the Stable export. "~" is a non-breaking space.
STABLE = [
    '%1$s a échoué (HTTP %2$d). %3$s',
    'Impossible de joindre le service~: %s',
    'L’adresse du service doit utiliser HTTPS.',
    'Le service ne prend pas en charge la version 1 du protocole Site Portrait.',
    'Le document de découverte du service est invalide (%s).',
    'Le document de découverte du service n’est pas un JSON valide.',
    'Le service n’a pas publié de document de découverte Site Portrait (code HTTP %d).',
    'Saisissez l’adresse HTTPS du service, par exemple https://service.example.',
    'Nombre d’utilisateurs par rôle. Jamais de noms, d’identifiants de connexion ni d’{adresses_courriel}.',
    'Nombre d’utilisateurs',
    'Nombre de publications par type et par état, de fichiers médias, de termes de taxonomie et de commentaires; taille des dossiers uploads, plugins et themes. Des nombres seulement, jamais de contenu.',
    'Volume de contenu',
    'Moteur et version de la base de données, taille totale, nombre de tables, plus grosses tables, taille des options chargées automatiquement. Ni identifiants d’accès ni préfixe des tables.',
    'Base de données',
    'Famille du système d’exploitation, serveur web, version, extensions et limites de PHP, OPcache, nombre de processeurs, mémoire et espace disque. Ni noms d’hôte, ni adresses IP, ni chemins d’accès.',
    'Serveur',
    'Thèmes installés avec leur version, thème actif et thème parent, mise à jour disponible.',
    'Thèmes',
    'Extensions installées avec leur version, leur état et la mise à jour disponible; extensions indispensables (must-use) et drop-ins.',
    'Extensions',
    'Version de WordPress et mise à jour disponible, langues, résumé du multisite, type d’environnement, HTTPS, type de permaliens, indicateurs de débogage, état du cron, détection des caches d’objets et de pages.',
    'Cœur de WordPress',
    'La notification du service',
    'Le service a renvoyé des clés qui ne correspondent pas à son document de découverte.',
    'Le service a renvoyé une réponse invalide (scopes).',
    'Le service a renvoyé une réponse invalide (pairing_id).',
    'L’échange du code avec le service',
    'Ce site est déjà connecté à un service. Déconnectez-le d’abord.',
    'Le service a renvoyé un code d’autorisation invalide.',
    'La demande de connexion a expiré ou n’a pas été lancée depuis ce site. Veuillez recommencer.',
    'Sélectionnez au moins une catégorie de données à partager.',
    'Vous n’avez pas l’autorisation de gérer Site Portrait.',
    'Résultat',
    'Catégories de données',
    'Requête',
    'Adresse IP',
    'Date',
    'Requêtes reçues par l’API Site Portrait au cours des 90 derniers jours.',
    'Journal des accès',
    'Déconnecter ce site du service?',
    'La déconnexion prend effet immédiatement~: le service ne peut plus rien lire et sa clé est supprimée de ce site. Le service en est ensuite informé.',
    'Déconnecter',
    'Générer une nouvelle clé du site',
    'Clés du service approuvées~: %s',
    'Clé du site~: %s',
    'Clés',
    'Facultatif. Une adresse IP ou une plage CIDR par ligne (IPv4 ou IPv6). Si la liste est remplie, les requêtes provenant d’autres adresses sont refusées.',
    'Adresses IP autorisées',
    'Identifiant {de_jumelage}',
    'en attente de confirmation par le service',
    'Connecté le',
    'Compte',
    'Service connecté',
    'Annuler',
    'Connecter',
    'En cliquant sur Connecter, vous êtes redirigé vers le service pour vous identifier et approuver. Le service reçoit alors l’adresse de ce site et une clé publique, et ce site enregistre la clé publique du service.',
    'Mode réseau~: le service pourra aussi lister les adresses de tous les sites de ce réseau, ainsi que leurs nombres pour les catégories cochées.',
    'Pourquoi le service le demande~: %s',
    'Le service ne peut lire que les catégories que vous cochez. Il ne peut jamais rien modifier sur ce site. Vous pouvez changer ce choix ou vous déconnecter à tout moment.',
    'Données que le service peut lire',
    'Conditions d’utilisation',
    'Politique de confidentialité',
    'Confidentialité',
    'Service',
    'Connecter ce site à %s?',
    'Rechercher le service',
    'Fournie par le service. Ce site lira la description du service à cette adresse et vous l’affichera avant toute autre action.',
    'Adresse du service',
    'Site Portrait permet à un service de votre choix (par exemple un hébergeur) de lire une description technique de ce site afin de recommander un hébergement adapté. L’extension reste inactive tant que vous n’avez pas connecté de service, et rien n’est envoyé nulle part avant votre confirmation.',
    'Le mode développement est actif (SITE_PORTRAIT_DEV_MODE)~: le HTTP non chiffré et les adresses locales sont acceptés. Ne l’utilisez jamais sur un site en production.',
    'Le site est déconnecté et le service en a été informé.',
    'Le site est déconnecté et le service ne peut plus lire aucune donnée. Toutefois, le service n’a pas pu être informé~: %s',
    'Une nouvelle clé du site a été générée. Le service la prendra en compte automatiquement.',
    'Réglages enregistrés.',
    'Réglages enregistrés, mais ces entrées de la liste d’adresses autorisées ont été ignorées, car ce ne sont pas des adresses ou des plages IP valides~: %s',
    'Le site est maintenant connecté. Le service peut lire les catégories de données que vous avez sélectionnées.',
    'Le service a renvoyé une erreur~: %s',
    'La connexion a été refusée du côté du service.',
    'Le lien que vous avez suivi a expiré, ou vous n’avez pas l’autorisation de connecter ce site.',
    'Les informations du service ont expiré. Veuillez rechercher le service de nouveau.',
    'Site Portrait décrit l’ensemble du serveur et de la base de données. Sur un réseau multisite, l’extension doit donc être activée sur le réseau par un super administrateur. Activée sur un seul site, elle ne fait rien~: désactivez-la ici, puis activez-la sur le réseau depuis l’administration du réseau.',
    'Réglages',
    'Site Portrait',
    'https://ctrlweb.ca',
    'ctrlweb',
    'Permet à tout service compatible de votre choix de lire de façon sécurisée un portrait technique de votre site afin de recommander un hébergement adapté.',
    'ctrlweb Site Portrait',
]

# Readme strings, in the order of the Stable Readme export.
README = [
    'Permettez à tout service compatible de votre choix de lire de façon sécurisée un portrait technique de votre site (versions, serveur, base de données, contenu) pour recommander un hébergement.',
    'ctrlweb Site Portrait',
    'Lisez <code>docs/PROTOCOL.md</code>. Ce document liste ce qu’un service doit implémenter, avec des exemples et des vecteurs de test.',
    'HTTPS est obligatoire. Pour le développement local seulement, définissez <code>SITE_PORTRAIT_DEV_MODE</code> à <code>true</code>, avec un type d’environnement <code>local</code> ou <code>development</code> et un hôte en <code>.test</code>, en <code>.localhost</code> ou une adresse de bouclage.',
    'Un mot de passe d’application donne à un service toutes les permissions de l’utilisateur qui l’a créé, et n’importe qui peut le réutiliser s’il l’obtient. Cette extension ne donne qu’un accès en lecture aux catégories choisies, avec des requêtes signées à usage unique.',
    'Le site ne stocke que la clé publique du service, qui ne permet pas d’envoyer des requêtes. La clé privée du site est aussi stockée; elle permet seulement de signer des réponses au nom de votre site, et on peut la remplacer depuis la page de réglages (Générer une nouvelle clé du site) ou en se déconnectant.',
    'Non. L’API est en lecture seule. La seule chose qu’un service peut faire en plus de lire, c’est mettre fin à la connexion.',
    'Comment créer un service compatible?',
    'Mon site est sur localhost ou utilise HTTP.',
    'Pourquoi ne pas utiliser un mot de passe d’application?',
    'Et si quelqu’un vole ma base de données?',
    'Le service peut-il modifier mon site?',
    'Les conditions d’utilisation et la politique de confidentialité du service s’appliquent aux données qu’il reçoit. Leurs adresses sont affichées avant la connexion et sur la page de réglages.',
    'Ce qui est envoyé, à qui et quand~:',
    'Cette extension connecte votre site à <strong>un seul service externe, choisi et saisi par l’administrateur du site</strong>. Aucun service n’est intégré, et l’extension ne contacte aucun serveur tant qu’un administrateur n’a pas saisi l’adresse d’un service et demandé de le rechercher.',
    'Le code de l’extension est distribué sous licence GPL, version 2 ou ultérieure (GPL-2.0-or-later). La spécification du protocole et les schémas JSON du dossier <code>docs/</code> sont distribués sous licence Creative Commons Attribution 4.0 (CC-BY-4.0), afin que tout le monde puisse implémenter un service compatible.',
    'Le protocole complet (découverte, {jumelage}, signature des requêtes, points de terminaison, erreurs, schémas JSON et vecteurs de test) se trouve dans <code>docs/PROTOCOL.md</code> et <code>docs/schema/</code>. Le filtre <code>site_portrait_scope_data</code> permet à d’autres extensions d’ajouter des données à une catégorie.',
    'Pour choisir le bon hébergement, il faut connaître son site~: versions de WordPress et de PHP, extensions et thèmes, taille de la base de données, nombre de publications et de fichiers médias, mémoire et processeur du serveur, caches en place… ctrlweb Site Portrait permet à <strong>un service de votre choix</strong> (généralement un hébergeur ou une agence) de lire ces informations de façon sécurisée, sans lui donner de compte administrateur.',
    '<strong>Quand l’administrateur clique sur «~Déconnecter~» ou supprime l’extension~:</strong> le site informe le service de la fin de la connexion (adresse du site et identifiant de connexion).',
    '<strong>Pendant la connexion~:</strong> le service peut demander le portrait. Le site ne répond qu’aux requêtes signées et ne renvoie que les catégories que vous avez cochées (voir la description pour le contenu de chacune). Sur un réseau multisite, la liste des adresses des sites est aussi accessible au service.',
    '<strong>Quand l’administrateur clique sur «~Connecter~» et approuve sur le service~:</strong> le navigateur de l’administrateur est redirigé vers la page d’autorisation du service avec l’adresse de votre site, le nom du site, les catégories cochées et une clé publique. Le site envoie ensuite au service, de serveur à serveur, le code d’autorisation, sa clé publique, les adresses des points de terminaison de son API Site Portrait, la version de l’extension et les catégories accordées.',
    '<strong>Quand l’administrateur clique sur «~Rechercher le service~»~:</strong> le site demande <code>https://&lt;service&gt;/.well-known/site-portrait</code> pour afficher le nom du service, sa politique de confidentialité et les données demandées. Seule une requête HTTP standard est envoyée (elle contient l’adresse de votre site dans l’en-tête User-Agent).',
    'Le service peut maintenant demander le portrait. Vous pouvez changer les catégories ou vous déconnecter à tout moment.',
    'Cliquez sur <strong>Connecter</strong>~: vous êtes redirigé vers le service pour vous identifier et approuver, puis ramené à votre tableau de bord.',
    'L’extension lit la description du service (<code>/.well-known/site-portrait</code>) et vous affiche son nom, sa politique de confidentialité et les données qu’il demande. Cochez les catégories que vous acceptez de partager.',
    'Dans <strong>Réglages → Site Portrait</strong>, saisissez l’adresse fournie par le service (par exemple <code>https://service.example</code>).',
    '<strong>Prête pour le multisite.</strong> Sur un réseau, un super administrateur connecte l’ensemble du réseau depuis l’administration du réseau.',
    '<strong>Transparente.</strong> Un journal des accès montre chaque requête (date, adresse IP, catégories). Liste d’adresses IP autorisées facultative, limitation du nombre de requêtes, déconnexion en un clic et rotation des clés.',
    '<strong>Aucun mot de passe à divulguer.</strong> Au lieu d’un mot de passe, le site et le service échangent des clés publiques. Chaque requête est signée (HTTP Message Signatures, RFC 9421, avec Ed25519) et ne peut servir qu’une fois. Même une copie de votre base de données ne permet pas de se faire passer pour le service.',
    '<strong>Lecture seule et données minimales.</strong> Le service ne peut jamais modifier votre site. L’extension ne partage jamais de mots de passe, de clés, de valeurs de <code>wp-config.php</code>, de noms d’utilisateur ni d’{adresses_courriel}, de contenu de publications, de chemins de fichiers, de préfixe de base de données ni d’adresses IP du serveur.',
    '<strong>Vous choisissez ce qui est partagé.</strong> Sept catégories (cœur de WordPress, extensions, thèmes, serveur, base de données, volume de contenu, nombre d’utilisateurs) peuvent être cochées ou décochées à tout moment.',
    '<strong>N’importe quel service compatible.</strong> L’extension n’est liée à aucune entreprise, pas même à son auteur. Elle implémente Site Portrait, un protocole ouvert documenté dans <code>docs/PROTOCOL.md</code> (inclus dans l’extension), afin que tout le monde puisse créer un service compatible.',
    '<strong>Désactivée par défaut.</strong> Rien ne se passe et rien n’est envoyé tant que vous n’avez pas saisi l’adresse d’un service et approuvé la connexion.',
    'Services externes',
    'Licences',
    'Pour les développeurs',
    'Fonctionnement',
    'Première version~: découverte, {jumelage} avec PKCE et clés Ed25519, API REST signée, sept catégories de données, journal des accès, liste d’adresses IP autorisées, limitation du nombre de requêtes, rotation des clés, mode réseau multisite.',
]

LOCALES = {
    'fr_CA': {'name': 'French (Canada)', 'plural': 'nplurals=2; plural=n > 1;'},
    'fr_FR': {'name': 'French (France)', 'plural': 'nplurals=2; plural=n > 1;'},
}


def localize(text, locale):
    for token, value in TOKENS[locale].items():
        text = text.replace(token, value)
    if locale == 'fr_FR':
        # Non-breaking space before ; ? ! (but never inside HTML entities such as &lt;).
        text = re.sub(r'&\w+;|\s?([;?!])', lambda m: m.group(0) if m.group(0).startswith('&') else NBSP + m.group(1), text)
    return text.replace('~', NBSP)


def po_escape(text):
    return text.replace('\\', '\\\\').replace('"', '\\"')


def unescape(text):
    return re.sub(r'\\(.)', lambda m: {'n': '\n', 't': '\t'}.get(m.group(1), m.group(1)), text)


def fill(template, translations, locale, out):
    blocks = open(template, encoding='utf-8').read().rstrip('\n').split('\n\n')
    header, entries = blocks[0], blocks[1:]
    assert len(entries) == len(translations), f'{template}: {len(entries)} entries, {len(translations)} translations'
    meta = LOCALES[locale]
    header = re.sub(r'in French \(Canada\)', f'in {meta["name"]}', header)
    header = re.sub(r'"Language: [^"]*\\n"', f'"Language: {locale}\\\\n"', header)
    header = re.sub(r'"PO-Revision-Date: [^"]*\\n"', '"PO-Revision-Date: ' + datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M+0000') + '\\\\n"', header)
    result = [header]
    for block, translation in zip(entries, translations):
        msgid = ''.join(re.findall(r'"(.*)"', re.search(r'^msgid ((?:".*"\n?)+)', block, re.M).group(1)))
        text = localize(translation, locale)
        # Placeholders must survive translation unchanged.
        assert sorted(re.findall(r'%(?:\d\$)?[sd]', unescape(msgid))) == sorted(re.findall(r'%(?:\d\$)?[sd]', text)), (msgid, text)
        assert sorted(re.findall(r'</?\w+>', unescape(msgid))) == sorted(re.findall(r'</?\w+>', text)), (msgid, text)
        block = re.sub(r'^msgstr ".*"$', 'msgstr "' + po_escape(text) + '"', block, flags=re.M)
        result.append(block)
    open(out, 'w', encoding='utf-8').write('\n\n'.join(result) + '\n')


def main():
    stable, readme, out_dir = sys.argv[1:4]
    for locale in LOCALES:
        fill(stable, STABLE, locale, f'{out_dir}/ctrlweb-site-portrait-{locale}.po')
        fill(readme, README, locale, f'{out_dir}/ctrlweb-site-portrait-readme-{locale}.po')


if __name__ == '__main__':
    main()
