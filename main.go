package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const (
	datadir         = "/root/data"
	version         = 1
	indexFileName   = "iexported.json"
	authcookie      = "iexported_auth"
	csrfcookie      = "iexported_csrf"
	cacheTTL        = 5 * time.Minute
	rateLimitMax    = 100
	rateLimitWin    = 1 * time.Minute
	loginRateLimit  = 5
	loginRateWindow = 15 * time.Minute
	cookieTTL       = 72 * 3600 // 72 hours
)

type chatentry struct {
	Filename     string   `json:"filename"`
	DisplayName  string   `json:"display_name"`
	MessageCount int      `json:"message_count"`
	IsContact    bool     `json:"is_contact"`
	IsGroup      bool     `json:"is_group"`
	IsEmail      bool     `json:"is_email"`
	Participants []string `json:"participants"`
}

func makeAuthCookieValue(expiresAt time.Time) string {
	payload := fmt.Sprintf("%d", expiresAt.Unix())
	mac := hmac.New(sha256.New, authSecret)
	_, _ = mac.Write([]byte(payload))
	sig := mac.Sum(nil)

	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return payloadB64 + "." + sigB64
}

func setAuthCookie(c *gin.Context) {
	expiresAt := time.Now().Add(time.Duration(cookieTTL) * time.Second)
	val := makeAuthCookieValue(expiresAt)
	c.SetCookie(authcookie, val, cookieTTL, "/", "", httpsEnabled, true)
	// Note: SameSite is set on successful login; renewing here keeps the original cookie attributes in most browsers.
}

func verifyAuthCookieValue(v string) (bool, error) {
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return false, errors.New("invalid token format")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false, errors.New("invalid payload encoding")
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false, errors.New("invalid signature encoding")
	}

	mac := hmac.New(sha256.New, authSecret)
	_, _ = mac.Write(payloadBytes)
	expected := mac.Sum(nil)
	if !hmac.Equal(sigBytes, expected) {
		return false, errors.New("invalid signature")
	}

	expUnix, err := strconv.ParseInt(string(payloadBytes), 10, 64)
	if err != nil {
		return false, errors.New("invalid expiry")
	}
	if time.Now().Unix() > expUnix {
		return false, errors.New("expired")
	}
	return true, nil
}

type exporterindex struct {
	Version     int         `json:"version"`
	GeneratedAt string      `json:"generated_at"`
	Chats       []chatentry `json:"chats"`
}

type snapshot struct {
	Name string        `json:"name"`
	Data exporterindex `json:"data"`
}

type snapshotCache struct {
	data      []snapshot
	timestamp time.Time
	mu        sync.RWMutex
	maxSize   int // Maximum number of chats to cache
}

type rateLimiter struct {
	requests map[string][]time.Time
	mu       sync.Mutex
}

var (
	cache         = &snapshotCache{}
	limiter       = &rateLimiter{requests: make(map[string][]time.Time)}
	loginLimiter  = &rateLimiter{requests: make(map[string][]time.Time)}
	csrfTokens    = &sync.Map{} // stores CSRF tokens: token -> expiry time
	phoneRegex    = regexp.MustCompile(`^\+?[0-9]{5,15}$`)
	contactRegex  = regexp.MustCompile(`^[A-Za-z]`)
	passwordHash  string
	authSecret    []byte
	httpsEnabled  bool
	manifestMu    sync.RWMutex
	manifest      = map[string]struct{}{}
	rescanRunning atomic.Bool
	logLevel      int32
)

const (
	logError int32 = 0
	logWarn  int32 = 1
	logInfo  int32 = 2
	logDebug int32 = 3
)

func setLogLevelFromEnv() {
	s := strings.ToLower(strings.TrimSpace(os.Getenv("LOG_LEVEL")))
	switch s {
	case "", "warn", "warning":
		atomic.StoreInt32(&logLevel, logWarn)
	case "error":
		atomic.StoreInt32(&logLevel, logError)
	case "info":
		atomic.StoreInt32(&logLevel, logInfo)
	case "debug":
		atomic.StoreInt32(&logLevel, logDebug)
	default:
		atomic.StoreInt32(&logLevel, logWarn)
		log.Printf("log: unknown LOG_LEVEL %q, defaulting to warn", s)
	}
}

func logf(level int32, format string, args ...any) {
	if atomic.LoadInt32(&logLevel) < level {
		return
	}
	log.Printf(format, args...)
}

func logln(level int32, args ...any) {
	if atomic.LoadInt32(&logLevel) < level {
		return
	}
	log.Println(args...)
}

func runHealthcheck() int {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8765/api/health", nil)
	if err != nil {
		return 1
	}

	resp, err := client.Do(req)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 1
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return 1
	}

	var payload struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		return 1
	}
	if payload.Status != "ok" {
		return 1
	}

	return 0
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--healthcheck" {
		os.Exit(runHealthcheck())
	}

	if _, err := os.Stat(datadir); os.IsNotExist(err) {
		log.Fatalf("fatal: %s not found", datadir)
	}

	setLogLevelFromEnv()

	// Initialize password hash from environment
	passwordHash = os.Getenv("AUTH_PASSWORD")
	if passwordHash == "" {
		log.Fatalf("fatal: AUTH_PASSWORD environment variable not set")
	}

	// Secret used to sign authentication cookies (prevents user-forged cookies)
	authSecretStr := os.Getenv("AUTH_SECRET")
	if strings.TrimSpace(authSecretStr) == "" {
		// Ephemeral secret: secure, but cookies will become invalid on restart.
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("fatal: failed to generate ephemeral AUTH_SECRET: %v", err)
		}
		authSecret = b
		logln(logWarn, "security: AUTH_SECRET not set; using ephemeral in-memory secret, sessions will be invalid after restart")
	} else {
		authSecret = []byte(authSecretStr)
	}

	// Check if HTTPS is enabled
	httpsStr := os.Getenv("HTTPS_ENABLED")
	httpsEnabled = httpsStr == "true" || httpsStr == "1"
	if httpsEnabled {
		logln(logInfo, "HTTPS enabled: setting secure cookie flags")
	}

	// Initialize cache with higher limits for large datasets
	cache.maxSize = 30000 // Support up to 30k conversations

	logln(logInfo, "iexported starting - initializing snapshot cache")
	loadManifest()

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(rateLimitMiddleware())
	r.Use(securityHeadersMiddleware())

    // Static files
	r.StaticFile("/", "./static/index.html")
	r.StaticFile("/style.css", "./static/style.css")
	r.StaticFile("/script.js", "./static/script.js")
	r.StaticFile("/sw.js", "./static/sw.js")
	r.StaticFile("/manifest.json", "./static/manifest.json")

	// Icons
	r.StaticFile("/favicon-96x96.png", "./static/favicon-96x96.png")
	r.StaticFile("/favicon.svg", "./static/favicon.svg")
	r.StaticFile("/favicon.ico", "./static/favicon.ico")
	r.StaticFile("/apple-touch-icon.png", "./static/apple-touch-icon.png")
	r.StaticFile("/manifest-192x192.png", "./static/manifest-192x192.png")
	r.StaticFile("/manifest-512x512.png", "./static/manifest-512x512.png")

	r.GET("/api/csrf", handleCSRFToken)
	r.GET("/api/health", handleHealth)
	r.GET("/api/snapshots", handleSnapshots)
	r.POST("/api/login", handleLogin)

	auth := r.Group("/")
	auth.Use(authMiddleware())
	{
		auth.POST("/api/rescan", csrfMiddleware(), handleRescan)
		auth.StaticFS("/view", http.Dir(datadir))
	}

	listenAddr := ":8765"

	logf(logInfo, "iexported listening on %s", listenAddr)
	if err := r.Run(listenAddr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// Security headers middleware
func securityHeadersMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "SAMEORIGIN")
        c.Header("X-XSS-Protection", "1; mode=block")

        // Relax CSP for exported chat files in /view (iframe content)
        if strings.HasPrefix(c.Request.URL.Path, "/view/") {
            // Allow external images/media and inline handlers/styles in the iframe content
            c.Header("Content-Security-Policy",
                "default-src 'self'; " +
                    "script-src 'self' 'unsafe-inline'; " +
                    "style-src 'self' 'unsafe-inline'; " +
                    "img-src * data: blob:; " +
                    "media-src *; " +
                    "frame-ancestors 'self'")
        } else {
            // Stricter CSP for the application shell
            c.Header("Content-Security-Policy",
                "default-src 'self'; " +
                    "script-src 'self'; " +
                    "style-src 'self' 'unsafe-inline'; " +
                    "img-src 'self' data:; " +
                    "frame-ancestors 'self'")
        }

        c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
        c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        c.Next()
    }
}

// Rate limiting middleware
func rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Exempt data-heavy paths from general rate limiting
		if isDataPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		ip := c.ClientIP()
		if !limiter.allow(ip) {
			logf(logWarn, "rate limit exceeded for %s", ip)
			c.JSON(429, gin.H{"error": "too many requests"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// Paths that serve larger, chat-related data should not be rate limited
func isDataPath(p string) bool {
	if strings.HasPrefix(p, "/view/") {
		return true
	}
	if p == "/api/snapshots" {
		return true
	}
	if p == "/api/csrf" {
		return true
	}
	return false
}

// CSRF middleware
func csrfMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("X-CSRF-Token")
		if token == "" {
			logf(logWarn, "csrf: missing token from %s", c.ClientIP())
			c.AbortWithStatusJSON(403, gin.H{"error": "csrf token missing"})
			return
		}

		expiry, ok := csrfTokens.Load(token)
		if !ok {
			logf(logWarn, "csrf: invalid token from %s", c.ClientIP())
			c.AbortWithStatusJSON(403, gin.H{"error": "csrf token invalid"})
			return
		}

		if time.Now().After(expiry.(time.Time)) {
			csrfTokens.Delete(token)
			logf(logWarn, "csrf: expired token from %s", c.ClientIP())
			c.AbortWithStatusJSON(403, gin.H{"error": "csrf token expired"})
			return
		}

		csrfTokens.Delete(token) // Single-use token
		c.Next()
	}
}

// Authentication middleware
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		v, err := c.Cookie(authcookie)
		if err != nil {
			logf(logWarn, "security: unauthorized access attempt from %s to %s", c.ClientIP(), c.Request.URL.Path)
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
			return
		}
		ok, verr := verifyAuthCookieValue(v)
		if !ok {
			logf(logWarn, "security: invalid auth cookie from %s to %s: %v", c.ClientIP(), c.Request.URL.Path, verr)
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
			return
		}
		setAuthCookie(c)
		c.Next()
	}
}

// Generate CSRF token
func handleCSRFToken(c *gin.Context) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		logf(logError, "csrf: failed to generate token: %v", err)
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	tokenStr := hex.EncodeToString(token)
	expiry := time.Now().Add(15 * time.Minute)
	csrfTokens.Store(tokenStr, expiry)

	c.JSON(200, gin.H{"token": tokenStr})
}

// Handle login with bcrypt verification and stricter rate limiting
func handleLogin(c *gin.Context) {
	ip := c.ClientIP()

	// Check login rate limit (stricter than general rate limit)
	if !loginLimiter.allowWithLimit(ip, loginRateLimit, loginRateWindow) {
		logf(logWarn, "security: login rate limit exceeded for %s", ip)
		c.JSON(429, gin.H{"error": "too many login attempts"})
		return
	}

	var body struct {
		Password  string `json:"password"`
		CSRFToken string `json:"csrf_token"`
	}
	if err := c.BindJSON(&body); err != nil {
		logf(logWarn, "security: login invalid request from %s: %v", ip, err)
		c.JSON(400, gin.H{"error": "bad request"})
		return
	}

	// Verify CSRF token
	expiry, ok := csrfTokens.Load(body.CSRFToken)
	if !ok || time.Now().After(expiry.(time.Time)) {
		logf(logWarn, "security: login csrf token invalid from %s", ip)
		c.JSON(403, gin.H{"error": "csrf token invalid"})
		return
	}

	// Verify password (support both plaintext and bcrypt)
	var passwordMatch bool
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(body.Password)); err == nil {
		passwordMatch = true
	} else if body.Password == passwordHash {
		// Fallback for plaintext password (for backwards compatibility)
		passwordMatch = true
	}

	if passwordMatch {
		csrfTokens.Delete(body.CSRFToken) // Only delete on successful login
		c.SetSameSite(http.SameSiteLaxMode)
		setAuthCookie(c)
		logf(logInfo, "security: login successful from %s", ip)
		c.JSON(200, gin.H{"status": "ok"})
	} else {
		logf(logWarn, "security: login failed attempt from %s", ip)
		c.JSON(401, gin.H{"error": "wrong password"})
	}
}

// Health check endpoint
func handleHealth(c *gin.Context) {
	c.JSON(200, gin.H{
		"status": "ok",
		"timestamp": time.Now().Unix(),
		"version": version,
	})
}

func handleRescan(c *gin.Context) {
	logln(logInfo, "rescan: initiated")
	if !rescanRunning.CompareAndSwap(false, true) {
		c.JSON(200, gin.H{"status": "ok"})
		return
	}
	go func() {
		defer rescanRunning.Store(false)
		fullRescanOverwrite()
	}()
	c.JSON(200, gin.H{"status": "ok"})
}

// Handle snapshots with caching
func handleSnapshots(c *gin.Context) {
	v, err := c.Cookie(authcookie)
	if err != nil {
		c.JSON(200, gin.H{"authenticated": false})
		return
	}
	ok, _ := verifyAuthCookieValue(v)
	if !ok {
		c.JSON(200, gin.H{"authenticated": false})
		return
	}
	setAuthCookie(c)

	snapshotDirs, err := listSnapshotDirs()
	if err != nil {
		c.JSON(500, gin.H{"error": "internal error"})
		return
	}

	snapshots := make([]snapshot, 0, len(snapshotDirs))
	for _, dir := range snapshotDirs {
		snapshotPath := filepath.Join(datadir, dir)
		idx, err := loadOrBuildSnapshotIndex(snapshotPath, false)
		if err != nil {
			logf(logWarn, "snapshots: failed to load %s: %v", dir, err)
			continue
		}
		snapshots = append(snapshots, snapshot{Name: dir, Data: idx})
		manifestMu.Lock()
		manifest[dir] = struct{}{}
		manifestMu.Unlock()
	}
	c.Header("Content-Type", "application/json")
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.JSON(200, snapshots)
}

func loadManifest() {
	dirs, err := listSnapshotDirs()
	if err != nil {
		logf(logWarn, "manifest: failed to list data dir: %v", err)
		return
	}
	manifestMu.Lock()
	defer manifestMu.Unlock()
	manifest = map[string]struct{}{}
	for _, d := range dirs {
		manifest[d] = struct{}{}
	}
}

func listSnapshotDirs() ([]string, error) {
	entries, err := os.ReadDir(datadir)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs)
	return dirs, nil
}

func loadOrBuildSnapshotIndex(snapshotPath string, overwrite bool) (exporterindex, error) {
	indexPath := filepath.Join(snapshotPath, indexFileName)
	if !overwrite {
		idx, err := readSnapshotIndex(indexPath)
		if err == nil {
			return idx, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return exporterindex{}, err
		}
	}

	idx, err := buildSnapshotIndexFromHTML(snapshotPath)
	if err != nil {
		return exporterindex{}, err
	}
	if err := writeSnapshotIndexAtomic(indexPath, idx); err != nil {
		return exporterindex{}, err
	}
	return idx, nil
}

func readSnapshotIndex(indexPath string) (exporterindex, error) {
	b, err := os.ReadFile(indexPath)
	if err != nil {
		return exporterindex{}, err
	}
	var idx exporterindex
	if err := json.Unmarshal(b, &idx); err != nil {
		return exporterindex{}, err
	}
	return idx, nil
}

func writeSnapshotIndexAtomic(indexPath string, idx exporterindex) error {
	b, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	tmpPath := indexPath + ".tmp"
	if err := os.WriteFile(tmpPath, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, indexPath)
}

func buildSnapshotIndexFromHTML(snapshotPath string) (exporterindex, error) {
	entries, err := os.ReadDir(snapshotPath)
	if err != nil {
		return exporterindex{}, err
	}

	var chats []chatentry
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".html") {
			chat, err := processChatFile(filepath.Join(snapshotPath, entry.Name()))
			if err != nil {
				logf(logWarn, "processsnapshot: error processing %s: %v", entry.Name(), err)
				continue
			}
			chats = append(chats, chat)
		}
	}

	sort.Slice(chats, func(i, j int) bool {
		return chats[i].DisplayName < chats[j].DisplayName
	})

	idx := exporterindex{
		Version:     version,
		GeneratedAt: time.Now().Format(time.RFC3339),
		Chats:       chats,
	}
	return idx, nil
}

func fullRescanOverwrite() {
	dirs, err := listSnapshotDirs()
	if err != nil {
		logf(logWarn, "rescan: failed to list data dir: %v", err)
		return
	}
	for _, dir := range dirs {
		idx, err := loadOrBuildSnapshotIndex(filepath.Join(datadir, dir), true)
		if err != nil {
			logf(logWarn, "rescan: failed %s: %v", dir, err)
			continue
		}
		_ = idx
		manifestMu.Lock()
		manifest[dir] = struct{}{}
		manifestMu.Unlock()
	}
}

func processChatFile(filepath string) (chatentry, error) {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return chatentry{}, err
	}

	filename := filepath[strings.LastIndex(filepath, "/")+1:]
	rawName := strings.TrimSuffix(filename, ".html")
	messageCount := strings.Count(string(content), "class=\"message\"")

	isGroup := strings.HasPrefix(rawName, "Group chat - ")
	var participants []string

	if isGroup {
		participants = strings.Split(strings.TrimPrefix(rawName, "Group chat - "), ", ")
		sort.Slice(participants, func(i, j int) bool {
			iIsPhone := phoneRegex.MatchString(participants[i])
			jIsPhone := phoneRegex.MatchString(participants[j])
			if !iIsPhone && jIsPhone {
				return true
			}
			if iIsPhone && !jIsPhone {
				return false
			}
			return participants[i] < participants[j]
		})
	}

	isEmail := strings.Contains(rawName, "@")
	isContact := contactRegex.MatchString(rawName) && !isEmail && !isGroup

	return chatentry{
		Filename:     filename,
		DisplayName:  rawName,
		MessageCount: messageCount,
		IsContact:    isContact,
		IsGroup:      isGroup,
		IsEmail:      isEmail,
		Participants: participants,
	}, nil
}

// Cache methods
func (sc *snapshotCache) get() []snapshot {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.data
}

func (sc *snapshotCache) invalidate() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.data = []snapshot{}
	sc.timestamp = time.Time{}
}

// Rate limiter methods
func (rl *rateLimiter) allow(ip string) bool {
	return rl.allowWithLimit(ip, rateLimitMax, rateLimitWin)
}

func (rl *rateLimiter) allowWithLimit(ip string, maxRequests int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	requests := rl.requests[ip]

	// Remove old requests outside the window
	var valid []time.Time
	for _, t := range requests {
		if now.Sub(t) < window {
			valid = append(valid, t)
		}
	}

	if len(valid) >= maxRequests {
		return false
	}

	valid = append(valid, now)
	rl.requests[ip] = valid
	return true
}