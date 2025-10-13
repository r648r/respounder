# Respounder

🇫🇷 **Français** · [🇬🇧 English](README.en.md)

**Respounder** est un scanner **LLMNR / mDNS** défensif (*honeypot* réseau). Il
interroge en boucle le réseau local avec des noms de machines qui **n'existent
pas**. Sur un réseau sain, personne ne répond. Si une réponse arrive, c'est
qu'un *poisoner* — typiquement [Responder](https://github.com/lgandx/Responder)
— est actif et usurpe ces noms pour capturer des authentifications NTLM.

> Réécriture/extension en Go de l'outil original
> [`codeexpress/respounder`](https://github.com/codeexpress/respounder) — voir
> [Crédits](#crédits). Ajoute la détection **mDNS**, le scan **multi-interfaces**,
> la détection **continue** et un mode **contre-empoisonnement** (`-spoof`).

## Démos (cas d'usage)

> Captures réelles du lab Docker ([`lab/`](lab/)) — terminal défenseur en haut,
> terminal de l'attaquant (Responder) en bas.

**1. Détection — démasquer un poisoner**
respounder interroge des noms d'hôte fictifs ; toute réponse trahit Responder, qui
empoisonne en croyant piéger des victimes.

![Détection](docs/01-detection.gif)

**2. Contre-empoisonnement (`-spoof`) — noyer le butin**
Une fois l'attaquant repéré, respounder lui envoie des dizaines de fausses victimes
à IP variées : ses logs de capture deviennent inexploitables.

![Spoof](docs/02-spoof.gif)

**3. Déception (`-art`) — chat Machiavel dans le terminal de l'attaquant**
respounder injecte des séquences d'échappement dans le nom interrogé : l'écran de
l'attaquant s'efface et y voit s'animer un chat récitant Machiavel.

![Art](docs/03-art.gif)

## Objectif

L'empoisonnement LLMNR/NBT-NS/mDNS est l'une des premières techniques utilisées
lors d'une intrusion sur un domaine Windows. Respounder répond à deux besoins :

- **Détecter** en continu la présence d'un tel attaquant sur le réseau : tout
  `[RESPONDER DETECTED]` signale un empoisonnement en cours, puisque les noms
  interrogés sont fictifs.
- **Leurrer et contre-empoisonner** (option `-spoof`) : une fois l'attaquant
  repéré, Respounder émet des requêtes avec des **IP sources usurpées** et des
  noms de machines réalistes. Le Responder de l'attaquant croit voir affluer des
  dizaines de victimes inexistantes et son butin se retrouve noyé sous de
  fausses entrées inexploitables.

> ⚠️ **Cadre d'utilisation** — L'écoute réseau et surtout l'émission de paquets
> à IP source usurpée (`-spoof`, qui nécessite les droits root) ne doivent être
> réalisées que sur un réseau dont vous êtes responsable, dans un cadre
> défensif et autorisé.

## Fonctionnement

1. À chaque cycle (`-interval`), une requête LLMNR et/ou mDNS est envoyée sur
   chaque interface pour un ou plusieurs noms d'hôte.
2. Toute réponse reçue est signalée `[RESPONDER DETECTED]` (le nom interrogé
   n'existant pas, seule une machine malveillante peut répondre).
3. Si `-spoof N` est activé, `N` sondes à IP usurpée sont envoyées une seule
   fois par responder détecté pour empoisonner son butin.

## Compilation

```bash
go build -o respounder .
```

## Utilisation

```bash
# Détection simple sur toutes les interfaces (aucun privilège particulier)
./respounder

# Cibler une interface et un nom d'hôte précis
./respounder -interface eth0 -hostname Administrator

# Noms d'hôte aléatoires réalistes, rattachés à un domaine
./respounder -random -domain corp.local

# LLMNR uniquement, cycle de 10 s, mode verbeux
./respounder -protocol llmnr -interval 10s -v

# Contre-empoisonnement : 5 fausses victimes par responder détecté (root requis)
sudo ./respounder -random -domain corp.local -spoof 5 -interval 10s
```

### Options

| Flag | Description | Défaut |
|------|-------------|--------|
| `-hostname` | Nom(s) d'hôte à rechercher, séparés par des virgules | `Administrator` |
| `-random` | Génère des noms d'hôte aléatoires réalistes | `false` |
| `-domain` | Domaine ajouté au nom d'hôte (ex : `corp.local`) | — |
| `-interface` | Interface(s) réseau, séparées par des virgules | toutes |
| `-ip` | Adresse IP source à utiliser | auto |
| `-protocol` | Protocole : `llmnr`, `mdns` ou `both` | `both` |
| `-interval` | Intervalle entre deux scans | `30s` |
| `-spoof` | Nb de sondes à IP usurpée par responder détecté (**root**) | `0` |
| `-art` | Déception active : anime un chat citant Machiavel dans le terminal d'un poisoner à l'écoute | `false` |
| `-v` | Mode verbeux (affiche les sondes envoyées) | `false` |
| `-debug` | Fichier de log de trace | — |

## Lab de démonstration (Docker)

Le dossier [`lab/`](lab/) monte un lab à **deux hôtes isolés** sur un réseau
bridge dédié : un *attaquant* qui lance **Responder** et un *capteur* qui lance
**respounder**.

```bash
cd lab
docker compose up --build      # le capteur affiche [RESPONDER DETECTED]
docker compose down -v         # nettoyage
```

### 1. Côté défenseur — `respounder` démasque l'attaquant

```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Let's poison the poisoner — bottoms up.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Query: Administrator (random mode)
Interval: 5s
Interfaces: 1
   > [eth0] 192.168.166.3
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[RESPONDER DETECTED] 192.168.166.2 | From [eth0] 192.168.166.3 | Protocol: LLMNR | Query: DESKTOP-PP7Q6
[RESPONDER DETECTED] 192.168.166.2 | From [eth0] 192.168.166.3 | Protocol: mDNS  | Query: DESKTOP-PP7Q6.local
[RESPONDER DETECTED] 192.168.166.2 | From [eth0] 192.168.166.3 | Protocol: LLMNR | Query: ERP-GMEKTV
[RESPONDER DETECTED] 192.168.166.2 | From [eth0] 192.168.166.3 | Protocol: mDNS  | Query: ERP-GMEKTV.local
```

### 2. Côté attaquant — Responder mord à l'hameçon

```text
[*] [LLMNR]  Poisoned answer sent to 192.168.166.3 for name DESKTOP-PP7Q6
[*] [MDNS]   Poisoned answer sent to 192.168.166.3 for name DESKTOP-PP7Q6.local
[*] [LLMNR]  Poisoned answer sent to 192.168.166.3 for name ERP-GMEKTV
[*] [MDNS]   Poisoned answer sent to 192.168.166.3 for name ERP-GMEKTV.local
```

### 3. Contre-empoisonnement (`-spoof`) — on noie le butin de l'attaquant

Avec `-spoof 5`, Responder voit affluer des **victimes fictives à IP variées**
(`.86`, `.36`, `.111`, `.10`, `.243`, `.20`…). Ses logs de capture deviennent
inexploitables :

```text
[*] [LLMNR]  Poisoned answer sent to 192.168.166.86  for name ADMIN-KY2HCO.corp.local
[*] [MDNS]   Poisoned answer sent to 192.168.166.36  for name SRV-VL8BN.local
[*] [MDNS]   Poisoned answer sent to 192.168.166.111 for name USER-LEU9FI.local
[*] [LLMNR]  Poisoned answer sent to 192.168.166.10  for name DEV-6PXAM.corp.local
[*] [MDNS]   Poisoned answer sent to 192.168.166.243 for name ADMIN-EBOWQA.local
[*] [LLMNR]  Poisoned answer sent to 192.168.166.20  for name LAPTOP-99R4W.corp.local
```

### 4. Déception `-art` — un chat citant Machiavel dans le terminal de l'attaquant

Un poisoner **affiche le nom interrogé**. `-art` glisse des séquences d'échappement
ANSI dans ce nom : le terminal de l'attaquant s'efface et y voit s'animer un chat
(3 images en boucle) récitant Machiavel. Une image (trame LLMNR ≤ 255 o) ressemble à :

```text
[*] [LLMNR]  Poisoned answer sent to 192.168.166.3 for name \033[2J\033[H\033[2;4H  /\_/\ \033[3;4H ( o.o )\033[4;4H  > ^ < \033[6;2H\033[1;33m« The end justifies the means. »\033[0m
```

Rendu dans **son** terminal (les escapes effacent l'écran et positionnent le curseur) :

```text
   /\_/\
  ( o.o )
   > ^ <

 « The end justifies the means. »
```

```bash
respounder -art -interface eth0          # boucle d'animation (aucun privilège requis)
```

> N'agit que sur un attaquant **regardant Responder en direct** dans un terminal
> (le fichier de log stocke les octets bruts). Même cadre défensif/autorisé que `-spoof`.

## Sous le capot — couleurs & pilotage du terminal

Tout repose sur les **séquences d'échappement ANSI** : des octets de contrôle que
le terminal **interprète** au lieu de les afficher. Le caractère d'échappement est
`ESC` (`0x1b`, noté `\033` ou `\x1b`).

### Les couleurs (dans la sortie de respounder)

Un code `ESC[<n>m` (SGR) change l'attribut du texte qui suit ; `ESC[0m` réinitialise.

| Séquence | Effet |
|---|---|
| `\033[1;36m` | cyan gras — titres / bannière |
| `\033[1;35m` | magenta — libellés (`Query:`, `Interval:`…) |
| `\033[1;32m` | vert — valeurs (IP, compteurs) |
| `\033[1;31m` | rouge — alertes `[RESPONDER DETECTED]` |
| `\033[0m` | reset |

```go
const colorTitle = "\033[1;36m"
const colorReset = "\033[0m"
fmt.Fprintf(os.Stderr, "%sLet's poison the poisoner%s\n", colorTitle, colorReset)
```

### Le nettoyage + le pilotage du terminal de l'attaquant (`-art`)

Un poisoner **affiche le nom interrogé**. On glisse dans ce nom, en plus des
couleurs, des séquences qui **effacent l'écran** et **déplacent le curseur** —
le terminal de l'attaquant les exécute :

| Séquence | Effet |
|---|---|
| `\033[2J` | **efface tout l'écran** (le « clean ») |
| `\033[H` | curseur en haut à gauche (`row 1, col 1`) |
| `\033[<l>;<c>H` | place le curseur ligne `l`, colonne `c` (dessine le chat ligne par ligne) |
| `\033[1;33m … \033[0m` | citation en jaune gras |

Chaque image du chat est forgée par `buildArtName` :

```go
func buildArtName(frameIdx int, quote string) string {
    var b strings.Builder
    b.WriteString("\x1b[2J\x1b[H")                       // efface l'écran + curseur en haut
    for i, line := range catFrames[frameIdx] {
        fmt.Fprintf(&b, "\x1b[%d;4H%s", i+2, line)       // chaque ligne du chat, positionnée
    }
    fmt.Fprintf(&b, "\x1b[6;2H\x1b[1;33m« %s »\x1b[0m", quote) // citation en jaune
    return b.String()
}
```

Une **requête LLMNR par image** → quand Responder ré-affiche le nom, l'écran est
effacé puis redessiné : le chat **s'anime**. Contrainte : un label LLMNR encode sa
longueur sur **un octet**, donc chaque image fait **≤ 255 octets** (garanti au build).

## Crédits

- Outil original : **[`codeexpress/respounder`](https://github.com/codeexpress/respounder)**
  — l'idée de détecter Responder en interrogeant des noms LLMNR fictifs.
- Outil détecté / cible du lab : **[`lgandx/Responder`](https://github.com/lgandx/Responder)**
  (Laurent Gaffié) — le *poisoner* LLMNR/NBT-NS/mDNS de référence.
