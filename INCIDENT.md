# INCIDENT.md : requests compromis

**Scénario** Une version de `requests` 2.25.0 utilisée par Minishop est annoncée comme compromise.

**Nature de l'exercice.** Le scénario est fictif : la version réellement utilisée par MiniShop `requests==2.34.2` n'est pas compromise.
Pour illustrer la détection avec de vraies sorties, j'ai simulé l'incident en auditant une ancienne version vulnérable, `requests==2.25.0`, dans un fichier temporaire, sans toucher au projet.


## 1. Détection

**Objectif :** confirmer que Minishop est concerné

**Sources possibles**
- Annonce publique
- Alerte Dependabot
- Échec du `pip-audit` ou `trivy` dans la CI

**Commandes**
```bash
source .venv/bin/activate
python -m pip_audit -r app/requirements.txt
```

**Explication :** On compare chaque paquet de `requirements.txt` à une base de vulnérabilités connues. Si `request==2.25.0` est listée comme touchée 

**Sortie réelle (simulation)**
```text
Found 24 known vulnerabilities in 3 packages
Name     Version ID              Fix Versions
-------- ------- --------------- ------------
requests 2.25.0  PYSEC-2023-74   2.31.0
requests 2.25.0  PYSEC-2023-74   2.31.0
requests 2.25.0  PYSEC-2026-1873 2.32.0
requests 2.25.0  PYSEC-2026-1872 2.32.4
requests 2.25.0  PYSEC-2026-2275 2.33.0
requests 2.25.0  PYSEC-2026-1873 2.32.0
requests 2.25.0  PYSEC-2026-1872 2.32.4
requests 2.25.0  PYSEC-2026-2275 2.33.0
idna     2.10    PYSEC-2024-60   3.7
idna     2.10    PYSEC-2024-60   3.7
idna     2.10    PYSEC-2026-215  3.15
idna     2.10    PYSEC-2026-215  3.15
urllib3  1.26.20 PYSEC-2026-1999 2.5.0
urllib3  1.26.20 PYSEC-2026-1998 2.6.0
urllib3  1.26.20 PYSEC-2026-1994 2.6.0
urllib3  1.26.20 PYSEC-2026-1996 2.6.3
urllib3  1.26.20 PYSEC-2026-141  2.7.0
urllib3  1.26.20 PYSEC-2026-141  2.7.0
urllib3  1.26.20 PYSEC-2026-1999 2.5.0
urllib3  1.26.20 PYSEC-2026-1998 2.6.0
urllib3  1.26.20 PYSEC-2026-1994 2.6.0
urllib3  1.26.20 PYSEC-2026-1996 2.6.3
urllib3  1.26.20 PYSEC-2026-4177 2.8.0
urllib3  1.26.20 PYSEC-2026-4175 2.8.0
```
**Lecture :** `requests 2.25.0` est vulnérable, la correction la plus récente listée est `2.33.0`. Les dépendances indirectes `idna` et `urllib3` sont aussi touchées.

```bash
gh run list --workflow security --limit 5
```

**Explication :** On regarde si le scan quotidien est passé au rouge, si le code n'avait pas été modifié, cela signifierait qu'une nouvelle vulnérabilité a été publiée

**Conclusion :** Ces commandes nous confirme que des failles de sécurités ont été détectées. On ouvre l'incident et on note l'heure.



## 2. Évaluation d'exposition

**Objectif :** savoir si la version compromise a tourné, où elle a tourné et quand 

```bash
grep -n "^requests==" app/requirements.txt
```

**Explication :** On lit la version vérrouillée dans le dépôt

**Simulation de sortie**
```text
785:requests==2.25.0 \
```
**Lecture :** La version est bien déclarée dans le dépôt

```bash
pip show requests | grep -E "^(Name|Version)"
```

**Explication :** On vérifie la version réelement installée car elle peut être différente de celle du fichier. On ne sait pas encore si elle a servi

**Simulation de sortie**
```text
Name: requests
Version: 2.25.0
```

**Lecture :** La version compromise a bien été installée.

```bash
git log --oneline -S"requests==2.25.0" -- app/requirements.txt
```

**Explication :** On cherche le commit qui a changé la version de `requests` pour avoir la date à partir MiniShop a pu être exposé.

**Simulation de sortie**
```text
216f53e initial commit
```

**Lecture :** La version compromise est présente depuis le commit 216f53e ont peut donc retrouvé la date

```bash
cyclonedx-py requirements app/requirements.txt --of JSON -o sbom.json
python -c "import json; d=json.load(open('sbom.json')); print([c['description'][:60] for c in d['components'] if 'requests' in c['description']])"
```

**Explication :** On génère le SBOM (*Software Bill of Materials*) puis on l'ouvre et on ne garde que les composants dont la description contient `requests`. On cherche dans la description qui contient le texte `requests==...`. 

**Simulation de sortie**
```text
['requirements line 785: requests==2.25.0     --hash=sha256:2a']
```

**Lecture :** Le SBOM confirme confirme la version de `requests` déclarée dans ce build, cependant ça neprouve pas que le code a réellement servi.

```bash
docker images
docker run --rm minishop pip show requests
```

**Explication :** On liste les images construites et on vérifie la version à l'intérieur de l'image qui tourne.

```bash
docker logs minishop --since 48h | grep -i "fetch\|error"
```

**Explication :** On cherche les appels à `/fetch` 

**Conclusion :** On liste les environnements qui ont embarqué la version avec les dates

## 3. Confinement

**Objectif :** On veut empêcher la propagation sans détruire les preuves

```bash
docker stop minishop
```

**Explication :** On arrête le container pour que le code compromis ne puisse plus agir.

```bash
docker save minishop -o minishop-incident.tar
```

**Explication :** On garde une copie de l'image pour l'analyser.

```bash
docker logs minishop > incident-logs.txt
```

**Explication :** On sauvegarde les logs qui vont disparaître avec le container.

## 4. Correction

Dans app/requirements.in:

```text
requests!=2.25.0
```

**Explication :** On interdit la version compromise

```bash
cd app
pip-compile --upgrade-package requests --generate-hashes requirements.in -o requirements.txt
cd ..
```

**Explication :** On met à jour `requests` et on regénère les hashes.

```bash
pip install --require-hashes -r app/requirements.txt
```

**Explication :** On installe le nouveau fichier.

```bash
python -m pip_audit -r app/requirements.txt
```

**Explication :** On vérifie qu'il n'y a plus de nouvelles vulnérabilités 

**Sortie attendue :**
```text
No known vulnerabilities found
```

```bash
python -m pytest -q tests
bash verify.sh
```

**Explication :** On vérifie que la mise à jour n'a rien cassé et que tous les test sont passés.

```bash
git add app/requirements.in app/requirements.txt
git commit -m "fix: exclude compromised requests version"
git push
```

**Explication :** On garde les traces de la correction et on déclanche la CI

## 5. Rotation des secrets
Si le code compromis a pu être exécuté, tous les secrets doivent être considérés comme volés donc il faut les remplacer

| Secret | Action | Pourquoi |
|---|---|---|
| `SECRET_KEY` | en générer une nouvelle | l'ancienne a pu être lue, la changer invalide aussi les sessions existantes |
| Clé AWS / jetons d'API | révoquer puis recréer | un secret volé reste utilisable tant qu'il n'est pas révoqué |
| Jetons GitHub / CI | régénérer | le code compromis a pu les lire dans l'environnement |
| Mots de passe | forcer le changement | par précaution si la base a pu être lue |

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

**Explication :** On génère une valeur aléatoire cryptographiquement sûre pour la nouvelle `SECRET_KEY` puis on la change dans le `.env`

```bash
gitleaks detect -v
```

**Explication :** On vérifie qu'aucun secret se trouve dans l'historique Git

## 6. Retour d'expérience


### Ce qui a bien fonctionné
- **Dépendances verrouillées avec hashes** (`pip-compile --generate-hashes`) : aucune version malveillante ne s'installe automatiquement.
- **`pip-audit` et Trivy en CI**, avec un scan quotidien (cron) : une nouvelle vulnérabilité est détectée même sans changement de code.
- **SBOM CycloneDX généré par la CI** : on connaît la liste exacte des paquets de chaque build, sans fouiller à la main.
- **Un commit par correction** : `git log -S` permet de retrouver quand la version est entrée et sortie du dépôt.
- **Secrets hors du code** (`SECRET_KEY` via variable d'environnement, `.env` ignoré par Git).

### Ce qui a posé problème
- **La clé AWS reste dans l'historique Git** (commit `216f53e`, détectée par `gitleaks`). La supprimer du code ne suffit pas : en réel, il faut la révoquer.
- **Aucune réponse sur l'exécution réelle** : le SBOM et `pip show` prouvent ce qui est installé, pas ce qui a tourné. Sans logs exploitables des appels à `/fetch`, on ne peut pas conclure.
- **Les dépendances indirectes** (`idna`, `urllib3`) sont aussi touchées.
- **Dependabot peut proposer une version trop récente** : une version fraîchement publiée peut elle-même être compromise.

### Actions d'amélioration
| Action | Pourquoi |
|---|---|
| Ajouter un `cooldown` dans `dependabot.yml` | ne pas adopter une version le jour de sa publication |
| Garder les actions GitHub épinglées par SHA | un tag réécrit ne peut pas changer la CI |
| Limiter les sorties réseau du conteneur à la liste blanche de `/fetch` | un code compromis ne pourrait pas exfiltrer de données |
| Donner au processus le minimum de secrets | réduire ce qu'un code malveillant peut voler |
| Conserver les logs de façon centralisée | pouvoir répondre à « est-ce que ça a tourné ? » |
| Rotation régulière des secrets | limiter la durée d'utilité d'un secret volé |
| Faire un exercice à blanc, relire ce runbook | gagner du temps le jour réel |

### Leçon principale
Les hashes et le verrouillage protègent contre une **modification involontaire**, mais pas contre une version malveillante qu'on choisit d'adopter. La défense repose donc sur plusieurs couches : verrouillage, audit continu, inventaire (SBOM), confinement rapide et rotation des secrets.