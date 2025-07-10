package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/adithya16pillai/subsnare/utils"
)
 
var (
	verbose      = true
	totalScanned = 0
	totalFound   = 0
	mu           sync.Mutex
)

type SignatureMap map[string]string

func loadSignatures(path string) (SignatureMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sigMap SignatureMap
	err = json.Unmarshal(data, &sigMap)
	return sigMap, err
}

func fetchBody(url string) (string, error) {
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("http://" + url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func matchSignature(cname, body string, sigMap SignatureMap) bool {
	for domain, pattern := range sigMap {
		if strings.Contains(cname, domain) && strings.Contains(body, pattern) {
			return true
		}
	}
	return false
}

func processDomain(domain string, sigMap SignatureMap, wg *sync.WaitGroup) {
	defer wg.Done()

	cname, err := utils.GetCNAME(domain)
	mu.Lock()
	totalScanned++
	mu.Unlock()

	if err != nil || cname == "" {
		if verbose {
			fmt.Printf("[INFO] %s: No CNAME record found or error: %v\n", domain, err)
		}
		return
	}

	body, err := fetchBody(cname)
	if err != nil {
		if verbose {
			fmt.Printf("[INFO] %s --> %s: HTTP error: %v\n", domain, cname, err)
		}
		return
	}

	if matchSignature(cname, body, sigMap) {
		mu.Lock()
		totalFound++
		mu.Unlock()
		fmt.Printf("[!] Potential takeover: %s --> %s\n", domain, cname)
	} else if verbose {
		fmt.Printf("[SAFE] %s --> %s: No takeover pattern matched\n", domain, cname)
	}
}

func main() {
	file, err := os.Open("domains.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	sigMap, err := loadSignatures("signatures.json")
	if err != nil {
		panic(err)
	}

	scanner := bufio.NewScanner(file)
	var wg sync.WaitGroup

	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}

		wg.Add(1)
		go processDomain(domain, sigMap, &wg)
	}

	wg.Wait()
	fmt.Println("Scan complete.")
	fmt.Printf("✔ %d domains scanned\n", totalScanned)
	fmt.Printf("⚠ %d potential takeovers found\n", totalFound)
	fmt.Println("Scan complete.")
}
