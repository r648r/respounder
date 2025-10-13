package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	Version            = "1.3"
	Timeout            = 3 * time.Second
	Interval           = 30 * time.Second
	LLMNRMulticastAddr = "224.0.0.252"
	LLMNRPort          = 5355
	MDNSMulticastAddr  = "224.0.0.251"
	MDNSPort           = 5353
	DefaultHostname    = "Administrator"
	colorReset         = "\033[0m"
	colorTitle         = "\033[1;36m"
	colorLabel         = "\033[1;35m"
	colorFlag          = "\033[1;33m"
	colorDesc          = "\033[0;37m"
	colorValue         = "\033[1;32m"
)

var (
	out = os.Stdout
	dbg = log.New(io.Discard, "", 0)

	debugFlag   = flag.String("debug", "", "Creates a debug log file with trace (ex: respounder.log)")
	verboseFlag = flag.Bool("v", false, "Verbose mode: displays interfaces used")
	hostname    = flag.String("hostname", DefaultHostname, "Hostname(s) to search for, comma-separated (ex: Administrator or Admin,Server,PC-001)")
	ifaceName   = flag.String("interface", "", "Network interface(s) to use, comma-separated (ex: eth0 or eth0,docker0,eth1)")
	ipAddr      = flag.String("ip", "", "Source IP address to use (ex: 192.168.1.10)")
	interval    = flag.Duration("interval", Interval, "Polling interval (ex: 30s, 1m)")
	randomNames = flag.Bool("random", false, "Generate random hostnames")
	domain      = flag.String("domain", "", "Domain name to append to hostname (ex: domain.com)")
	protocol    = flag.String("protocol", "both", "Protocol to use: llmnr, mdns, or both")
	spoofCount  = flag.Int("spoof", 0, "Number of spoofed IP probes to send after the first real probe (requires root)")
	artFlag     = flag.Bool("art", false, "Active deception: animate a Machiavelli-quoting cat into a watching poisoner's terminal (via the queried name)")

	// timestamp of last probe sent per interface
	lastProbeTimes   = make(map[string]time.Time)
	lastProbeTimesMu sync.Mutex

	// Map pour associer chaque IP usurpée à un hostname unique
	spoofedIPHostnames   = make(map[string]string)
	spoofedIPHostnamesMu sync.RWMutex

	// Map pour traquer les responders déjà détectés (pour éviter de spoofer à chaque cycle)
	detectedResponders   = make(map[string]bool)
	detectedRespondersMu sync.Mutex
)

type ifaceInfo struct {
	Name string
	IP   net.IP
}

type responderDetection struct {
	ResponderIP   string
	SourceIP      string
	SourceIface   string
	ReceivedOnIP  string
	ReceivedIface string
	Hostname      string
	Protocol      string
}

// generateRandomIPInSubnet génère une IP aléatoire dans le même sous-réseau
func generateRandomIPInSubnet(baseIP net.IP, mask net.IPMask) net.IP {
	ip := make(net.IP, 4)
	copy(ip, baseIP.To4())

	// Générer une partie aléatoire pour l'adresse hôte
	for i := 0; i < 4; i++ {
		if mask[i] != 0xff {
			// Cette partie n'est pas fixée par le masque, on peut la randomiser
			hostBits := ^mask[i]
			randomHost := byte(rand.Intn(int(hostBits) + 1))
			ip[i] = (ip[i] & mask[i]) | (randomHost & hostBits)
		}
	}

	// Éviter .0 (réseau) et .255 (broadcast) dans le dernier octet
	if ip[3] == 0 {
		ip[3] = byte(rand.Intn(254) + 1)
	}
	if ip[3] == 255 {
		ip[3] = byte(rand.Intn(254) + 1)
	}

	return ip
}

// calculateChecksum calcule le checksum IP/UDP
func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// generateRandomHostname génère un nom d'hôte aléatoire réaliste
func generateRandomHostname() string {
	prefixes := []string{
		"ADMIN", "WORKSTATION", "LAPTOP", "SRV",
		"VEN", "GDF", "ERP", "ESX",
		"DESKTOP", "PC", "USER", "DEV", "TEST", "PROD", "SERVER",
	}

	// Générer un suffixe alphanumérique aléatoire (5-6 caractères, style Windows)
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	suffixLen := rand.Intn(2) + 5 // 5 ou 6 caractères
	suffix := make([]byte, suffixLen)
	for i := range suffix {
		suffix[i] = chars[rand.Intn(len(chars))]
	}

	prefix := prefixes[rand.Intn(len(prefixes))]
	hostname := prefix + "-" + string(suffix)

	// Ajouter le domaine si spécifié
	if *domain != "" {
		hostname = hostname + "." + *domain
	}

	return hostname
}

// getOrCreateHostnameForIP retourne un hostname unique pour une IP spoofée
// Si l'IP a déjà un hostname associé, on le réutilise pour la cohérence
func getOrCreateHostnameForIP(ip string) string {
	spoofedIPHostnamesMu.RLock()
	if hostname, exists := spoofedIPHostnames[ip]; exists {
		spoofedIPHostnamesMu.RUnlock()
		return hostname
	}
	spoofedIPHostnamesMu.RUnlock()

	// Générer un nouveau hostname pour cette IP
	spoofedIPHostnamesMu.Lock()
	defer spoofedIPHostnamesMu.Unlock()

	// Double-check après avoir acquis le lock d'écriture
	if hostname, exists := spoofedIPHostnames[ip]; exists {
		return hostname
	}

	hostname := generateRandomHostname()
	spoofedIPHostnames[ip] = hostname
	return hostname
}

// ── Mode -art : déception active ──────────────────────────────────────────
// Un poisoner (Responder) affiche le nom interrogé dans son terminal. En
// glissant des séquences d'échappement ANSI dans ce nom, on efface son écran
// et on y anime un chat qui récite Machiavel. Les labels LLMNR sont binaire-safe
// (<= 255 octets) : on envoie une trame par image, ce qui produit l'animation.

var catFrames = [][]string{
	{`  /\_/\ `, ` ( o.o )`, `  > ^ < `},
	{`  /\_/\ `, ` ( -.- )`, `  > ^ < `},
	{`  /\_/\ `, ` ( o.o )`, `  > w < `},
}

var machiavelli = []string{
	"The end justifies the means.",
	"It is better to be feared than loved.",
	"He who wishes to be obeyed must know how to command.",
	"Men judge more by the eye than by the hand.",
	"Never was anything great achieved without danger.",
	"A prince must have no other aim than war.",
}

// buildArtName forge le nom interrogé : efface l'écran, dessine une image du
// chat et affiche une citation. Tout passe par les octets du QNAME.
func buildArtName(frameIdx int, quote string) string {
	var b strings.Builder
	b.WriteString("\x1b[2J\x1b[H") // efface l'écran + curseur en haut
	for i, line := range catFrames[frameIdx] {
		fmt.Fprintf(&b, "\x1b[%d;4H%s", i+2, line) // ligne i, colonne 4
	}
	if quote != "" {
		fmt.Fprintf(&b, "\x1b[6;2H\x1b[1;33m« %s »\x1b[0m", quote) // citation en jaune
	}
	return b.String()
}

// sendArtLLMNR émet une requête LLMNR dont le QNAME est l'image à injecter, puis
// lit une éventuelle réponse : un poisoner répond à TOUT (même à notre trame
// d'art), ce qui nous donne son IP. Renvoie l'IP du poisoner, ou "" si aucun.
func sendArtLLMNR(srcIP net.IP, name string) string {
	if len(name) > 255 {
		return "" // un label LLMNR tient sur 1 octet de longueur
	}
	cNameLen := fmt.Sprintf("%02x", len(name))
	reqHex := "0001" + "0000" + "0001" + "0000" + "0000" + "0000" + cNameLen + hex.EncodeToString([]byte(name)) + "0000010001"
	payload, err := hex.DecodeString(reqHex)
	if err != nil {
		return ""
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: srcIP, Port: 0})
	if err != nil {
		return ""
	}
	defer conn.Close()
	if _, err := conn.WriteToUDP(payload, &net.UDPAddr{IP: net.ParseIP(LLMNRMulticastAddr), Port: LLMNRPort}); err != nil {
		return ""
	}
	_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buf := make([]byte, 1024)
	if _, addr, err := conn.ReadFromUDP(buf); err == nil && addr != nil {
		return addr.IP.String()
	}
	return ""
}

// runArt boucle l'animation : chaque image est poussée vers le multicast LLMNR.
func runArt(ifaces []ifaceInfo) {
	fmt.Fprintf(os.Stderr, "%s[art]%s Machiavelli cat — injecting into watching poisoners' terminals (Ctrl-C to stop)\n", colorTitle, colorReset)
	seen := make(map[string]bool)
	for frame := 0; ; frame++ {
		quote := machiavelli[(frame/len(catFrames))%len(machiavelli)]
		name := buildArtName(frame%len(catFrames), quote)
		if len(name) > 255 {
			name = buildArtName(frame%len(catFrames), "")
		}
		for _, ii := range ifaces {
			if ip := sendArtLLMNR(ii.IP, name); ip != "" && !seen[ip] {
				seen[ip] = true
				fmt.Fprintf(out, "\033[1;31m[RESPONDER DETECTED]\033[0m %s%s%s | poisoner hooked — injecting Machiavelli cat\n",
					colorValue, ip, colorReset)
			}
		}
		time.Sleep(220 * time.Millisecond)
	}
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%sRespounder%s %sv%s%s\n", colorTitle, colorReset, colorValue, Version, colorReset)
		fmt.Fprintf(os.Stderr, "%sLLMNR/mDNS scanner to detect active responders on your network.%s\n\n", colorDesc, colorReset)

		fmt.Fprintf(os.Stderr, "%sUsage%s: respounder [options]\n\n", colorLabel, colorReset)
		fmt.Fprintf(os.Stderr, "%sOptions%s:\n", colorLabel, colorReset)
		flag.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(os.Stderr, "  %s-%s%s", colorFlag, f.Name, colorReset)
			if !isBoolFlag(f) {
				if typ := flagValueType(f); typ != "" {
					fmt.Fprintf(os.Stderr, " <%s>", typ)
				} else {
					fmt.Fprintf(os.Stderr, " <valeur>")
				}
			}
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "    %s%s%s\n", colorDesc, f.Usage, colorReset)
			if def, ok := defaultValue(f); ok {
				fmt.Fprintf(os.Stderr, "    %sDefault value%s: %s%s%s\n", colorLabel, colorReset, colorValue, def, colorReset)
			}
		})

		fmt.Fprintf(os.Stderr, "\n%sExamples%s:\n", colorLabel, colorReset)
		fmt.Fprintf(os.Stderr, "  respounder -ip 192.168.1.100 -random\n")
		fmt.Fprintf(os.Stderr, "  respounder -interface eth0 -hostname Administrator\n")
		fmt.Fprintf(os.Stderr, "  respounder -interval 10s -debug\n")
	}
	flag.Parse()

	// Validate -protocol: an unknown value would silently send no probe at all.
	switch *protocol {
	case "llmnr", "mdns", "both":
	default:
		fmt.Fprintf(os.Stderr, "invalid -protocol %q (expected: llmnr, mdns, or both)\n", *protocol)
		os.Exit(1)
	}

	// Validate -interval: a negative interval is meaningless.
	if *interval < 0 {
		fmt.Fprintf(os.Stderr, "invalid -interval %q (must be >= 0)\n", *interval)
		os.Exit(1)
	}

	// Setup logging if debug flag is set
	logPath := *debugFlag
	if logPath != "" {
		if err := setupLogging(logPath); err != nil {
			fmt.Fprintf(os.Stderr, "warning: unable to enable debug: %v\n", err)
		}
	}

	ifaces, err := collectInterfaces(*ifaceName, *ipAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		printAvailableInterfaces()
		os.Exit(1)
	}
	if len(ifaces) == 0 {
		fmt.Fprintln(os.Stderr, "No valid IPv4 interface found.")
		printAvailableInterfaces()
		os.Exit(1)
	}

	// Afficher les informations de configuration
	fmt.Fprintln(os.Stderr, "\n"+colorTitle+"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"+colorReset)
	fmt.Fprintf(os.Stderr, "%sLet's poison the poisoner — bottoms up.%s\n", colorTitle, colorReset)
	fmt.Fprintln(os.Stderr, colorTitle+"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"+colorReset)

	fmt.Fprintf(os.Stderr, "%sQuery:%s %s%s%s", colorLabel, colorReset, colorValue, *hostname, colorReset)
	if *randomNames {
		fmt.Fprintf(os.Stderr, " %s(random mode)%s", colorDesc, colorReset)
	}
	fmt.Fprintln(os.Stderr)

	fmt.Fprintf(os.Stderr, "%sInterval:%s %s%s%s\n", colorLabel, colorReset, colorValue, *interval, colorReset)

	fmt.Fprintf(os.Stderr, "%sInterfaces:%s %s%d%s\n", colorLabel, colorReset, colorValue, len(ifaces), colorReset)
	for _, iface := range ifaces {
		fmt.Fprintf(os.Stderr, "   %s>%s [%s%s%s] %s%s%s\n",
			colorLabel, colorReset,
			colorFlag, iface.Name, colorReset,
			colorValue, iface.IP, colorReset)
	}

	fmt.Fprint(os.Stderr, colorTitle+"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"+colorReset+"\n\n")

	// Mode -art : injecte un chat animé dans le terminal d'un poisoner à l'écoute.
	if *artFlag {
		runArt(ifaces)
	}

	// Préparer la liste des hostnames à tester
	var hostnames []string
	if *randomNames {
		// En mode random, on générera un nouveau nom à chaque fois
		hostnames = []string{"random"}
	} else {
		// Parse les hostnames séparés par des virgules
		hostnameList := strings.Split(*hostname, ",")
		for _, h := range hostnameList {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			// Ajouter le domaine si spécifié
			if *domain != "" {
				h = h + "." + *domain
			}
			// La requête LLMNR encode le nom dans un label unique (longueur sur 1 octet).
			if len(h) > 255 {
				fmt.Fprintf(os.Stderr, "warning: hostname %q skipped (exceeds 255 bytes)\n", h)
				continue
			}
			hostnames = append(hostnames, h)
		}
		if len(hostnames) == 0 {
			fmt.Fprintln(os.Stderr, "no valid hostname to query (set -hostname or use -random)")
			os.Exit(1)
		}
	}

	// Boucle de polling continue
	for {
		cycleStart := time.Now()

		// Déterminer quels protocoles utiliser
		useLLMNR := *protocol == "llmnr" || *protocol == "both"
		useMDNS := *protocol == "mdns" || *protocol == "both"

		// Calculer le nombre de goroutines à lancer
		protocolCount := 0
		if useLLMNR {
			protocolCount++
		}
		if useMDNS {
			protocolCount++
		}

		// Channel pour synchroniser les goroutines
		done := make(chan bool, len(ifaces)*len(hostnames)*protocolCount)

		// Scanner toutes les interfaces en parallèle avec tous les hostnames
		for _, ii := range ifaces {
			for _, hn := range hostnames {
				// Générer le hostname une seule fois pour LLMNR et mDNS
				var sharedHostname string
				if *randomNames {
					sharedHostname = generateRandomHostname()
					dbg.Printf("Nom généré : %s", sharedHostname)
				} else {
					sharedHostname = hn
				}

				// Lancer une goroutine pour LLMNR si activé
				if useLLMNR {
					go func(iface ifaceInfo, targetHostname string) {
						defer func() { done <- true }()

						// Afficher l'interface utilisée en mode verbose
						if *verboseFlag {
							interfaceKey := iface.Name + ":" + iface.IP.String()
							var timeSinceLastProbe string

							lastProbeTimesMu.Lock()
							if lastTime, exists := lastProbeTimes[interfaceKey]; exists {
								elapsed := time.Since(lastTime).Seconds()
								timeSinceLastProbe = fmt.Sprintf(" (+%.2fs)", elapsed)
							} else {
								timeSinceLastProbe = ""
							}
							lastProbeTimes[interfaceKey] = time.Now()
							lastProbeTimesMu.Unlock()

							fmt.Fprintf(os.Stderr, "Sending LLMNR probe from [%s] %s for %s%s\n", iface.Name, iface.IP, targetHostname, timeSinceLastProbe)
						}

						ctx, cancel := context.WithTimeout(context.Background(), Timeout)
						defer cancel()
						detection, err := sendLLMNRProbe(ctx, iface.IP, iface.Name, targetHostname)
						if err != nil {
							dbg.Printf("LLMNR probe error on %s %s: %v", iface.Name, iface.IP, err)
							return
						}
						if detection != nil {
							fmt.Fprintf(out, "\033[1;31m[RESPONDER DETECTED]\033[0m %s | From [%s] %s | Protocol: %s | Query: %s\n",
								detection.ResponderIP,
								detection.SourceIface, detection.SourceIP,
								detection.Protocol,
								detection.Hostname)

							// Si un responder est détecté et que le spoofing est activé, envoyer des paquets spoofés
							// MAIS seulement si on ne l'a pas déjà fait pour ce responder
							if *spoofCount > 0 {
								responderKey := detection.ResponderIP + ":" + detection.Protocol

								detectedRespondersMu.Lock()
								alreadySpoofed := detectedResponders[responderKey]
								if !alreadySpoofed {
									detectedResponders[responderKey] = true
									detectedRespondersMu.Unlock()

									mask, err := getSubnetMask(iface.IP)
									if err != nil {
										dbg.Printf("Failed to get subnet mask: %v", err)
									} else {
										dbg.Printf("First detection of %s (LLMNR) - Sending %d spoofed LLMNR probes from subnet", detection.ResponderIP, *spoofCount)
										go sendSpoofedLLMNRProbe(iface.IP, mask, *spoofCount)
									}
								} else {
									detectedRespondersMu.Unlock()
									dbg.Printf("Responder %s (LLMNR) already known - skipping spoofed probes", detection.ResponderIP)
								}
							}
						}
					}(ii, sharedHostname)
				}

				// Lancer une goroutine pour mDNS si activé
				if useMDNS {
					go func(iface ifaceInfo, targetHostname string) {
						defer func() { done <- true }()

						// Afficher l'interface utilisée en mode verbose
						if *verboseFlag {
							interfaceKey := iface.Name + ":" + iface.IP.String()
							var timeSinceLastProbe string

							lastProbeTimesMu.Lock()
							if lastTime, exists := lastProbeTimes[interfaceKey]; exists {
								elapsed := time.Since(lastTime).Seconds()
								timeSinceLastProbe = fmt.Sprintf(" (+%.2fs)", elapsed)
							} else {
								timeSinceLastProbe = ""
							}
							lastProbeTimes[interfaceKey] = time.Now()
							lastProbeTimesMu.Unlock()

							fmt.Fprintf(os.Stderr, "Sending mDNS probe from [%s] %s for %s%s\n", iface.Name, iface.IP, targetHostname, timeSinceLastProbe)
						}

						ctx, cancel := context.WithTimeout(context.Background(), Timeout)
						defer cancel()
						detection, err := sendMDNSProbe(ctx, iface.IP, iface.Name, targetHostname)
						if err != nil {
							dbg.Printf("mDNS probe error on %s %s: %v", iface.Name, iface.IP, err)
							return
						}
						if detection != nil {
							fmt.Fprintf(out, "\033[1;31m[RESPONDER DETECTED]\033[0m %s | From [%s] %s | Protocol: %s | Query: %s\n",
								detection.ResponderIP,
								detection.SourceIface, detection.SourceIP,
								detection.Protocol,
								detection.Hostname)

							// Si un responder est détecté et que le spoofing est activé, envoyer des paquets spoofés
							// MAIS seulement si on ne l'a pas déjà fait pour ce responder
							if *spoofCount > 0 {
								responderKey := detection.ResponderIP + ":" + detection.Protocol

								detectedRespondersMu.Lock()
								alreadySpoofed := detectedResponders[responderKey]
								if !alreadySpoofed {
									detectedResponders[responderKey] = true
									detectedRespondersMu.Unlock()

									mask, err := getSubnetMask(iface.IP)
									if err != nil {
										dbg.Printf("Failed to get subnet mask: %v", err)
									} else {
										dbg.Printf("First detection of %s (mDNS) - Sending %d spoofed mDNS probes from subnet", detection.ResponderIP, *spoofCount)
										go sendSpoofedMDNSProbe(iface.IP, mask, *spoofCount)
									}
								} else {
									detectedRespondersMu.Unlock()
									dbg.Printf("Responder %s (mDNS) already known - skipping spoofed probes", detection.ResponderIP)
								}
							}
						}
					}(ii, sharedHostname)
				}
			}
		}

		// Attendre que toutes les goroutines se terminent
		for i := 0; i < len(ifaces)*len(hostnames)*protocolCount; i++ {
			<-done
		}

		// Calculer le temps restant avant le prochain cycle
		elapsed := time.Since(cycleStart)
		if elapsed < *interval {
			time.Sleep(*interval - elapsed)
		}
	}
}

func setupLogging(logPath string) error {
	if logPath == "" {
		logPath = "respounder.log"
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	// On garde le fichier ouvert pendant la durée du processus.
	dbg = log.New(f, "", 0)
	dbg.SetPrefix("[" + time.Now().Format("02-Jan-2006 15:04:05 MST") + "]: ")
	return nil
}

func collectInterfaces(target string, targetIP string) ([]ifaceInfo, error) {
	sysIfs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("unable to list interfaces: %w", err)
	}
	var out []ifaceInfo

	// If a specific IP is requested
	if targetIP != "" {
		ip := net.ParseIP(targetIP)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address '%s'", targetIP)
		}
		ip = ip.To4()
		if ip == nil {
			return nil, fmt.Errorf("only IPv4 addresses are supported")
		}

		// Find the interface that has this IP
		for _, inf := range sysIfs {
			addrs, err := inf.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					if ipnet.IP.Equal(ip) {
						out = append(out, ifaceInfo{Name: inf.Name, IP: ip})
						return out, nil
					}
				}
			}
		}
		return nil, fmt.Errorf("no interface has IP '%s'", targetIP)
	}

	// If specific interfaces are requested (comma-separated)
	if target != "" {
		ifaceNames := strings.Split(target, ",")
		for _, ifaceName := range ifaceNames {
			ifaceName = strings.TrimSpace(ifaceName)
			if ifaceName == "" {
				continue
			}
			inf, err := net.InterfaceByName(ifaceName)
			if err != nil {
				return nil, fmt.Errorf("invalid interface '%s'", ifaceName)
			}
			if ip := firstUsableIPv4(inf); ip != nil {
				out = append(out, ifaceInfo{Name: inf.Name, IP: ip})
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("no valid IPv4 address found on specified interfaces")
		}
		return out, nil
	}

	// Otherwise, use all available interfaces
	for _, inf := range sysIfs {
		if ip := firstUsableIPv4(&inf); ip != nil {
			out = append(out, ifaceInfo{Name: inf.Name, IP: ip})
		}
	}
	return out, nil
}

func printAvailableInterfaces() {
	ifs, _ := net.Interfaces()
	fmt.Fprintln(os.Stderr, "Available interfaces:")
	for _, inf := range ifs {
		fmt.Fprintln(os.Stderr, "- "+inf.Name)
	}
}

func firstUsableIPv4(inf *net.Interface) net.IP {
	if inf == nil {
		return nil
	}
	if (inf.Flags&net.FlagUp) == 0 || (inf.Flags&net.FlagLoopback) != 0 {
		return nil
	}
	addrs, err := inf.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip := ipnet.IP.To4(); ip != nil && !ip.IsLoopback() {
				return ip
			}
		}
	}
	return nil
}

func sendLLMNRProbe(ctx context.Context, srcIP net.IP, srcIface string, name string) (*responderDetection, error) {
	// Construction de la trame LLMNR: TransactionID (0001), Flags (0000), QDCOUNT (0001), AN/NS/AR=0
	cNameLen := fmt.Sprintf("%02x", len(name))
	encCName := hex.EncodeToString([]byte(name))
	reqHex := "0001" + "0000" + "0001" + "0000" + "0000" + "0000" + cNameLen + encCName + "0000010001"
	payload, err := hex.DecodeString(reqHex)
	if err != nil {
		return nil, fmt.Errorf("invalid LLMNR payload: %w", err)
	}

	remote := &net.UDPAddr{IP: net.ParseIP(LLMNRMulticastAddr), Port: LLMNRPort}
	local := &net.UDPAddr{IP: srcIP, Port: 0}

	conn, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, fmt.Errorf("bind error: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(timeoutFromContext(ctx))
	_ = conn.SetDeadline(deadline)

	if _, err := conn.WriteToUDP(payload, remote); err != nil {
		return nil, fmt.Errorf("send error: %w", err)
	}

	buf := make([]byte, 2048)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil || n == 0 {
		return nil, nil
	}
	if addr != nil {
		// Get the local address that received the response
		localAddr := conn.LocalAddr().(*net.UDPAddr)

		return &responderDetection{
			ResponderIP:   addr.IP.String(),
			SourceIP:      srcIP.String(),
			SourceIface:   srcIface,
			ReceivedOnIP:  localAddr.IP.String(),
			ReceivedIface: srcIface, // Same interface since we bind to specific IP
			Hostname:      name,
			Protocol:      "LLMNR",
		}, nil
	}
	return nil, nil
}

func sendMDNSProbe(ctx context.Context, srcIP net.IP, srcIface string, name string) (*responderDetection, error) {
	// Construction de la trame mDNS (DNS query over multicast)
	// Format: TransactionID (0000), Flags (0000 for standard query), QDCOUNT (0001), AN/NS/AR=0

	// Pour mDNS, on extrait le nom de la machine (première partie avant le point)
	// et on ajoute toujours .local comme domaine mDNS standard
	deviceName := name
	if idx := strings.Index(name, "."); idx != -1 {
		deviceName = name[:idx]
	}
	mdnsName := deviceName + ".local"

	// Encoder le nom au format DNS (labels avec longueur)
	// Ex: "hostname.local" -> 08hostname05local00
	var encodedName string
	parts := strings.Split(strings.TrimSuffix(mdnsName, "."), ".")
	for _, part := range parts {
		if part != "" {
			encodedName += fmt.Sprintf("%02x", len(part)) + hex.EncodeToString([]byte(part))
		}
	}
	encodedName += "00" // Terminating null

	// mDNS query: TransactionID (0000), Flags (0000), Questions (0001), Answers/Authority/Additional (0000)
	reqHex := "0000" + "0000" + "0001" + "0000" + "0000" + "0000" + encodedName + "0001" + "0001"
	// Type A (0001), Class IN (0001)

	payload, err := hex.DecodeString(reqHex)
	if err != nil {
		return nil, fmt.Errorf("invalid mDNS payload: %w", err)
	}

	remote := &net.UDPAddr{IP: net.ParseIP(MDNSMulticastAddr), Port: MDNSPort}
	local := &net.UDPAddr{IP: srcIP, Port: 0}

	conn, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, fmt.Errorf("bind error: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(timeoutFromContext(ctx))
	_ = conn.SetDeadline(deadline)

	if _, err := conn.WriteToUDP(payload, remote); err != nil {
		return nil, fmt.Errorf("send error: %w", err)
	}

	buf := make([]byte, 2048)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil || n == 0 {
		return nil, nil
	}
	if addr != nil {
		// Get the local address that received the response
		localAddr := conn.LocalAddr().(*net.UDPAddr)

		return &responderDetection{
			ResponderIP:   addr.IP.String(),
			SourceIP:      srcIP.String(),
			SourceIface:   srcIface,
			ReceivedOnIP:  localAddr.IP.String(),
			ReceivedIface: srcIface,
			Hostname:      mdnsName,
			Protocol:      "mDNS",
		}, nil
	}
	return nil, nil
}

// sendSpoofedMulticastUDP envoie un paquet UDP multicast avec une IP source usurpée
func sendSpoofedMulticastUDP(spoofedSrcIP net.IP, dstIP net.IP, dstPort int, payload []byte) error {
	// Créer un raw socket pour IPv4
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("failed to create raw socket (need root): %w", err)
	}
	defer syscall.Close(fd)

	// Activer IP_HDRINCL pour construire notre propre header IP
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return fmt.Errorf("failed to set IP_HDRINCL: %w", err)
	}

	// Port source aléatoire
	srcPort := uint16(rand.Intn(65535-1024) + 1024)

	// Construire le paquet UDP
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], srcPort)         // Source port
	binary.BigEndian.PutUint16(udpHeader[2:4], uint16(dstPort)) // Destination port
	udpLength := uint16(8 + len(payload))
	binary.BigEndian.PutUint16(udpHeader[4:6], udpLength) // Length
	binary.BigEndian.PutUint16(udpHeader[6:8], 0)         // Checksum (0 for now)

	// Pseudo-header pour le checksum UDP
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], spoofedSrcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = syscall.IPPROTO_UDP
	binary.BigEndian.PutUint16(pseudoHeader[10:12], udpLength)

	// Calculer le checksum UDP
	checksumData := append(pseudoHeader, udpHeader...)
	checksumData = append(checksumData, payload...)
	checksum := calculateChecksum(checksumData)
	binary.BigEndian.PutUint16(udpHeader[6:8], checksum)

	// Construire le paquet UDP complet
	udpPacket := append(udpHeader, payload...)

	// Construire le header IP
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // Version 4, IHL 5
	ipHeader[1] = 0x00 // DSCP, ECN
	totalLength := uint16(20 + len(udpPacket))
	binary.BigEndian.PutUint16(ipHeader[2:4], totalLength)              // Total length
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(rand.Intn(65535))) // ID
	binary.BigEndian.PutUint16(ipHeader[6:8], 0)                        // Flags, Fragment offset
	ipHeader[8] = 64                                                    // TTL
	ipHeader[9] = syscall.IPPROTO_UDP                                   // Protocol
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)                      // Checksum (0 for now)
	copy(ipHeader[12:16], spoofedSrcIP.To4())                           // Source IP
	copy(ipHeader[16:20], dstIP.To4())                                  // Destination IP

	// Calculer le checksum IP
	ipChecksum := calculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], ipChecksum)

	// Paquet IP complet
	packet := append(ipHeader, udpPacket...)

	// Destination address structure
	addr := syscall.SockaddrInet4{
		Port: 0, // Ignored for raw sockets
	}
	copy(addr.Addr[:], dstIP.To4())

	// Envoyer le paquet
	err = syscall.Sendto(fd, packet, 0, &addr)
	if err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	return nil
}

// sendSpoofedLLMNRProbe envoie des requêtes LLMNR avec IPs spoofées
func sendSpoofedLLMNRProbe(realSrcIP net.IP, mask net.IPMask, count int) {
	dstIP := net.ParseIP(LLMNRMulticastAddr)

	// Envoyer count paquets avec des IPs spoofées
	for i := 0; i < count; i++ {
		spoofedIP := generateRandomIPInSubnet(realSrcIP, mask)
		spoofedIPStr := spoofedIP.String()

		// Obtenir ou créer un hostname unique pour cette IP spoofée
		spoofedHostname := getOrCreateHostnameForIP(spoofedIPStr)

		// Construire le payload LLMNR avec le hostname spécifique à cette IP
		cNameLen := fmt.Sprintf("%02x", len(spoofedHostname))
		encCName := hex.EncodeToString([]byte(spoofedHostname))
		reqHex := "0001" + "0000" + "0001" + "0000" + "0000" + "0000" + cNameLen + encCName + "0000010001"
		payload, err := hex.DecodeString(reqHex)
		if err != nil {
			dbg.Printf("invalid LLMNR payload for %s: %v", spoofedHostname, err)
			continue
		}

		err = sendSpoofedMulticastUDP(spoofedIP, dstIP, LLMNRPort, payload)
		if err != nil {
			dbg.Printf("Failed to send spoofed LLMNR from %s: %v", spoofedIPStr, err)
			continue
		}
		dbg.Printf("Sent spoofed LLMNR from %s for %s", spoofedIPStr, spoofedHostname)
		time.Sleep(10 * time.Millisecond) // Petit délai entre les paquets
	}
}

// sendSpoofedMDNSProbe envoie des requêtes mDNS avec IPs spoofées
func sendSpoofedMDNSProbe(realSrcIP net.IP, mask net.IPMask, count int) {
	dstIP := net.ParseIP(MDNSMulticastAddr)

	// Envoyer count paquets avec des IPs spoofées
	for i := 0; i < count; i++ {
		spoofedIP := generateRandomIPInSubnet(realSrcIP, mask)
		spoofedIPStr := spoofedIP.String()

		// Obtenir ou créer un hostname unique pour cette IP spoofée
		spoofedHostname := getOrCreateHostnameForIP(spoofedIPStr)

		// Pour mDNS, extraire le nom de la machine et ajouter .local
		deviceName := spoofedHostname
		if idx := strings.Index(spoofedHostname, "."); idx != -1 {
			deviceName = spoofedHostname[:idx]
		}
		mdnsName := deviceName + ".local"

		// Encoder le nom au format DNS
		var encodedName string
		parts := strings.Split(strings.TrimSuffix(mdnsName, "."), ".")
		for _, part := range parts {
			if part != "" {
				encodedName += fmt.Sprintf("%02x", len(part)) + hex.EncodeToString([]byte(part))
			}
		}
		encodedName += "00"

		// Construire le payload mDNS
		reqHex := "0000" + "0000" + "0001" + "0000" + "0000" + "0000" + encodedName + "0001" + "0001"
		payload, err := hex.DecodeString(reqHex)
		if err != nil {
			dbg.Printf("invalid mDNS payload for %s: %v", mdnsName, err)
			continue
		}

		err = sendSpoofedMulticastUDP(spoofedIP, dstIP, MDNSPort, payload)
		if err != nil {
			dbg.Printf("Failed to send spoofed mDNS from %s: %v", spoofedIPStr, err)
			continue
		}
		dbg.Printf("Sent spoofed mDNS from %s for %s", spoofedIPStr, mdnsName)
		time.Sleep(10 * time.Millisecond) // Petit délai entre les paquets
	}
}

// getSubnetMask récupère le masque de sous-réseau pour une IP donnée
func getSubnetMask(ip net.IP) (net.IPMask, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(ip) {
					return ipnet.Mask, nil
				}
			}
		}
	}

	// Par défaut, utiliser un /24
	return net.CIDRMask(24, 32), nil
}

func timeoutFromContext(ctx context.Context) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 {
			return d
		}
	}
	return Timeout
}

func defaultValue(f *flag.Flag) (string, bool) {
	if isBoolFlag(f) {
		if f.DefValue == "true" {
			return "true", true
		}
		return "", false
	}
	if f.DefValue == "" {
		return "", false
	}
	return f.DefValue, true
}

func isBoolFlag(f *flag.Flag) bool {
	if f == nil {
		return false
	}
	type boolFlag interface {
		flag.Value
		IsBoolFlag() bool
	}
	if bf, ok := f.Value.(boolFlag); ok && bf.IsBoolFlag() {
		return true
	}
	return false
}

func flagValueType(f *flag.Flag) string {
	if f == nil {
		return ""
	}
	// Avoid exposing internal type names when we can derive something meaningful.
	typeStr := fmt.Sprintf("%T", f.Value)
	// Expect patterns like *flag.stringValue. Keep the simple suffix.
	if strings.HasPrefix(typeStr, "*flag.") && strings.HasSuffix(typeStr, "Value") {
		trimmed := strings.TrimSuffix(strings.TrimPrefix(typeStr, "*flag."), "Value")
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}
