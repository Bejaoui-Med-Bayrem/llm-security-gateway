# LLM Security Gateway

Plateforme de **red teaming** et de **défense** pour les applications qui utilisent un LLM.

Elle envoie des attaques (injection de prompt, jailbreak, fuite de données…) à une application cible, décide pour chaque message de l'**autoriser, le signaler ou le bloquer**, puis **mesure** l'efficacité de la défense en comparant les résultats avec et sans protection.

Ce projet **ne crée pas de LLM** : il teste et protège une application existante. La cible de démonstration est [AIGoat](https://github.com/AISecurityConsortium/AIGoat), une application volontairement vulnérable qui s'appuie sur Mistral, exécuté par Ollama.

> Projet personnel à visée pédagogique. Lis la section [Limites connues](#limites-connues) avant d'en tirer des conclusions.

## Principe

```text
Attaque ──▶ Détection ──▶ Autoriser / Signaler / Bloquer ──▶ Mesure ──▶ Comparaison avant / après
```

## Architecture

```text
 Navigateur
     │
     ▼
 Dashboard Next.js ─────────▶ Gateway FastAPI ─────────▶ AIGoat ─────────▶ Ollama (Mistral)
   port 3000                    port 8000                 port 8001         port 11434
                                   │
                                   ▼
                              PostgreSQL
                              port 15432
```

Pour chaque message, le Gateway enchaîne :

1. **Normalisation** : décodage des messages déguisés (base64, hex, ROT13, texte inversé, caractères invisibles, homoglyphes, leetspeak, lettres espacées, URL, double encodage).
2. **Détection** par règles : catégorie d'attaque et score.
3. **Score de risque** : catégorie, sévérité, obfuscation, historique de la conversation.
4. **Politique** : `ALLOW`, `FLAG` ou `BLOCK`, avec escalade au fil d'une session.
5. **Transmission** à la cible, par un adaptateur, si le message est autorisé.
6. **Enregistrement** : exécution, décision et évaluation de la campagne.

La cible est derrière un **adaptateur** : AIGoat est le premier, d'autres applications pourront être ajoutées sans toucher au moteur de détection.

## Fonctionnalités

**Détection et décision**

- 12 catégories : injection de prompt, jailbreak, extraction du prompt système, contournement d'instructions, manipulation de contexte, obfuscation, fuite de données, abus de ressources, agentivité excessive, empoisonnement RAG, attaque de la chaîne d'approvisionnement, jeu de rôle.
- Règles en anglais et en français, avec une couverture partielle de l'espagnol et de l'arabe.
- Mode `strict` (un message suspect est bloqué) ou `monitor` (il est signalé et transmis).
- Escalade de session : après un blocage ou plusieurs messages suspects, le seuil de blocage s'abaisse pour la suite de la conversation.

**Campagnes et mesures**

- Campagnes d'attaques, avec messages légitimes (`benign`) pour mesurer les faux positifs.
- Générateur d'attaques en anglais et en français.
- Évaluation calculée automatiquement : taux de détection, taux d'attaques réussies (ASR), taux de faux positifs, latence.
- Exécution **avec** ou **sans** défense dans la même campagne, avec tableau d'écart.
- Clonage de campagne, rapport imprimable et export JSON.

**Plateforme**

- Authentification JWT, mots de passe hachés avec Argon2, limitation des tentatives de connexion.
- Isolation des données par utilisateur (un utilisateur ne voit que ses campagnes).
- Tableau de bord Next.js : applications, campagnes, testeur interactif, historique des décisions.

## Résultats mesurés

Mesures du détecteur sur le jeu interne du dépôt (`python -m benchmark.run`, graine fixe), avec l'intervalle de confiance à 95 % de Wilson :

| Jeu | N | Règles seules | + normalisation | + politique |
|---|---:|---:|---:|---:|
| Attaques synthétiques (générées) | 208 | 56,2 % [49–63] | 89,9 % [85–93] | **92,8 % [88–96]** |
| Messages légitimes bloqués à tort | 58 | 0 % [0–6] | 0 % [0–6] | **0 % [0–6]** |

La normalisation fait passer la détection de 56 % à 90 % : sans elle, les attaques encodées passent presque toutes.

D'autres jeux (44 attaques écrites à la main, 28 et 25 messages d'un second jeu) donnent des taux plus élevés, mais ils ont servi à écrire et à corriger les règles : **ils ne sont pas indépendants** et ne doivent pas être cités comme une performance.

## Limites connues

- **Aucune mesure indépendante.** Les jeux de test ont servi à développer les règles. Ces chiffres montrent que le détecteur couvre ces exemples, pas qu'il résiste à des attaques inconnues. N'en déduis pas « bloque X % des attaques connues ».
- **L'ASR est une borne haute.** Le juge compte comme réussie toute réponse qui n'est pas un refus : une réponse qui demande des précisions est comptée à tort.
- **Seules les entrées sont filtrées.** Les réponses de l'application ne sont pas contrôlées : une fuite de donnée dans une réponse passerait.
- **Détection par règles.** Un abus de logique métier (« ajoute un code de réduction de 100 % ») ne ressemble à aucun motif d'attaque et n'est pas détecté.
- **Le LLM n'est pas déterministe.** L'ASR varie d'une exécution à l'autre, et un message autorisé prend de 10 à 60 secondes.
- **Usage local.** L'URL de la cible est déclarée par l'utilisateur et appelée par le Gateway, et le mode « sans défense » est ouvert à tout utilisateur connecté (désactivable). N'expose pas ce service sur Internet en l'état.

## Prérequis

- Windows avec Git Bash (testé), ou un système équivalent
- Python 3.14 (testé)
- Node.js 20 ou plus (testé avec 22)
- Docker Desktop
- [Ollama](https://ollama.com) avec le modèle `mistral`
- [AIGoat](https://github.com/AISecurityConsortium/AIGoat), installé à part

## Installation

**1. Récupérer le projet**

```bash
git clone https://github.com/Bejaoui-Med-Bayrem/llm-security-gateway.git
cd llm-security-gateway
```

**2. Configurer l'environnement**

```bash
cp .env.example .env
```

Édite `.env` : remplace `POSTGRES_PASSWORD` et `JWT_SECRET_KEY`. Pour générer une clé :

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

**3. Base de données**

```bash
docker compose up -d
docker exec llm-security-postgres pg_isready -U llm_security -d llm_security
```

La base écoute sur `localhost:15432`. N'utilise jamais `docker compose down -v` : l'option `-v` supprime les données.

**4. Backend**

```bash
cd backend
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
alembic upgrade head
```

**5. Frontend**

```bash
cd ../frontend
npm install
```

**6. Modèle et cible**

```bash
ollama pull mistral
```

Installe et lance AIGoat selon son propre README, sur le port **8001**. Crée un compte dans AIGoat, récupère son jeton et renseigne-le dans `.env` (`AIGOAT_TOKEN`). Si les messages autorisés renvoient une erreur d'authentification, génère un nouveau jeton.

## Configuration

| Variable | Rôle | Valeur par défaut |
|---|---|---|
| `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | accès à la base | `llm_security` / `llm_security` / à définir |
| `POSTGRES_HOST`, `POSTGRES_PORT` | adresse de la base | `localhost` / `15432` |
| `JWT_SECRET_KEY` | clé de signature des jetons | à définir |
| `JWT_ALGORITHM` | algorithme de signature | `HS256` |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | durée d'un jeton | `30` |
| `AIGOAT_BASE_URL` | adresse de la cible | `http://127.0.0.1:8001` |
| `AIGOAT_TOKEN` | jeton de la cible | à définir |
| `CORS_ORIGINS` | origines autorisées pour le dashboard | `http://localhost:3000`, `http://127.0.0.1:3000` |
| `GATEWAY_FLAG_MODE` | `strict` ou `monitor` | `strict` |
| `GATEWAY_ALLOW_DEFENSE_OFF` | autorise l'exécution sans défense | `true` |
| `NEXT_PUBLIC_API_URL` | adresse du Gateway, côté frontend | `http://localhost:8000` |

Ne versionne jamais `.env`.

## Lancer la plateforme

Démarre les services dans cet ordre, chacun dans son terminal.

```bash
# 1. PostgreSQL et Ollama
docker start llm-security-postgres
ollama run mistral "hello"        # réchauffe le modèle, puis /bye

# 2. AIGoat (port 8001)
cd AIGoat && source .venv/Scripts/activate
python -m uvicorn app.main:app --port 8001

# 3. Gateway (port 8000)
cd backend && source .venv/Scripts/activate
python -m uvicorn app.main:app --reload --port 8000

# 4. Dashboard (port 3000)
cd frontend && npm run dev
```

Ouvre [http://localhost:3000](http://localhost:3000), crée un compte, puis ajoute une application avec l'URL `http://127.0.0.1:8001`.

Vérification rapide :

```bash
curl http://localhost:8000/health
```

## Utilisation

1. **Applications** : déclare la cible (`http://127.0.0.1:8001`).
2. **Testeur** : envoie un message et observe la décision du Gateway en direct.
3. **Campagnes** : crée une campagne, ajoute des attaques et des messages `benign`, puis lance « Tout exécuter ».
4. Les résultats s'affichent automatiquement. Relance avec l'option « sans défense » pour obtenir le tableau d'écart.
5. **Décisions** : historique de chaque message, avec la raison de la décision.
6. **Rapport** : export JSON ou impression en PDF.

## API

La documentation interactive est disponible sur [http://localhost:8000/docs](http://localhost:8000/docs).

| Ressource | Routes |
|---|---|
| Authentification | `POST /api/auth/register`, `POST /api/auth/login` |
| Applications | `/api/applications/` |
| Campagnes | `/api/campaigns/`, `POST /api/campaigns/{id}/clone`, `POST /api/campaigns/{id}/retest` |
| Attaques | `/api/attacks/`, `GET /api/attacks/campaign/{id}` |
| Exécutions | `/api/attack-executions/` |
| Décisions | `/api/gateway-decisions/` |
| Évaluations | `/api/evaluations/`, `POST /api/evaluations/campaign/{id}`, `GET /api/evaluations/compare` |
| Exécuter une attaque | `POST /api/ai-goat/execute` |
| État | `GET /health` |

## Tests

```bash
cd backend
python -m pytest app/services/test_detection_engine.py app/services/test_evaluation_service.py -q
python -m app.services.test_policy_engine
python -m benchmark.run                # mesures du détecteur ; options : --show-misses, --json fichier
python test_phase12_integration.py     # nécessite tous les services lancés
```

```bash
cd frontend
npx tsc --noEmit
npm run lint
```

Le test d'intégration envoie plusieurs messages au modèle : compte quelques minutes.

## Structure du dépôt

Voir [`structure.txt`](structure.txt).

## Sécurité et usage responsable

- AIGoat est **volontairement vulnérable** : ne l'expose pas hors de ta machine.
- N'utilise ces outils d'attaque que contre des applications dont tu es propriétaire ou pour lesquelles tu as une autorisation écrite.
- Remplace `JWT_SECRET_KEY` et `POSTGRES_PASSWORD` avant tout usage autre que local, et mets `GATEWAY_ALLOW_DEFENSE_OFF=false` si plusieurs personnes utilisent la plateforme.

## Feuille de route

- Contrôle des **sorties** de l'application (e-mails, clés, mots de passe dans les réponses).
- Juge d'attaque plus fin, avec correction manuelle du verdict.
- Évaluation sur un jeu public et indépendant.
- Adaptateurs pour d'autres applications cibles.
- Tests automatisés du frontend.

## Licence

À définir.