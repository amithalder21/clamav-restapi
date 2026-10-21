package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/redis/go-redis/v9"
)

//go:embed scan_dashboard.html
var dashboardHTML string

// defaultDashboardPathID is the 12-digit path segment the dashboard is served
// under (/api/v1/<id>) instead of a guessable name like /admin or /dashboard.
// It is obscurity layered on top of the JWT check on the data endpoint, not a
// substitute for it; override per environment with SCAN_DASHBOARD_PATH_ID.
const defaultDashboardPathID = "824339653470"

const (
	dashboardPageSize   = 100
	dashboardMaxRows    = 20000
	dashboardFetchers   = 16
	finalDayCacheTTL    = 31 * 24 * time.Hour
	openDayCacheTTL     = 60 * time.Second
	dayFinalGracePeriod = 15 * time.Minute
)

var dashboardPathRE = regexp.MustCompile(`^[0-9]{12}$`)

func dashboardPathID(env map[string]string) (string, bool) {
	v := env["SCAN_DASHBOARD_PATH_ID"]
	if v == "" {
		return defaultDashboardPathID, true
	}
	if !dashboardPathRE.MatchString(v) {
		return "", false
	}
	return v, true
}

type auditStore interface {
	ListKeys(ctx context.Context, prefix string) ([]string, error)
	GetObject(ctx context.Context, key string) ([]byte, error)
}

type dayCache interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, val []byte, ttl time.Duration)
}

type scanRow struct {
	ScanID   string           `json:"scan_id"`
	Filename string           `json:"filename"`
	At       string           `json:"at"`
	ScanMS   int64            `json:"scan_ms"`
	Engines  *EngineTimingsMS `json:"engine_ms,omitempty"`
}

type dashboardDeps struct {
	store   auditStore
	cache   dayCache
	now     func() time.Time
	maxRows int
}

func datePrefixes(now time.Time, days int) []string {
	out := make([]string, 0, days+1)
	for i := 0; i <= days; i++ {
		out = append(out, now.AddDate(0, 0, -i).Format("2006/01/02"))
	}
	return out
}

func dayIsFinal(day string, now time.Time) bool {
	start, err := time.ParseInLocation("2006/01/02", day, now.Location())
	if err != nil {
		return false
	}
	return now.After(start.AddDate(0, 0, 1).Add(dayFinalGracePeriod))
}

// queryRows returns every audit record for tenant uploaded within the last
// `days` days. Only keys under audit/<tenant>/ are ever listed or read.
func (d *dashboardDeps) queryRows(ctx context.Context, tenant string, days int) ([]scanRow, bool, error) {
	now := d.now()
	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour)

	var all []scanRow
	truncated := false
	for _, day := range datePrefixes(now, days) {
		rows, dayTruncated, err := d.loadDay(ctx, tenant, day, dayIsFinal(day, now))
		if err != nil {
			return nil, false, err
		}
		truncated = truncated || dayTruncated
		for _, r := range rows {
			if t, err := time.Parse(time.RFC3339, r.At); err == nil && t.Before(cutoff) {
				continue
			}
			all = append(all, r)
		}
	}
	if len(all) > d.maxRows {
		sortRows(all, "newest")
		all = all[:d.maxRows]
		truncated = true
	}
	return all, truncated, nil
}

func (d *dashboardDeps) loadDay(ctx context.Context, tenant string, day string, final bool) ([]scanRow, bool, error) {
	cacheKey := "dash:v1:" + tenant + ":" + day
	if d.cache != nil {
		if raw, ok := d.cache.Get(ctx, cacheKey); ok {
			var cached []scanRow
			if json.Unmarshal(raw, &cached) == nil {
				return cached, false, nil
			}
		}
	}

	keys, err := d.store.ListKeys(ctx, "audit/"+tenant+"/"+day+"/")
	if err != nil {
		return nil, false, err
	}
	truncated := false
	if len(keys) > d.maxRows {
		keys = keys[:d.maxRows]
		truncated = true
	}

	var (
		mu         sync.Mutex
		wg         sync.WaitGroup
		rows       = make([]scanRow, 0, len(keys))
		incomplete bool
		sem        = make(chan struct{}, dashboardFetchers)
	)
	for _, key := range keys {
		wg.Add(1)
		sem <- struct{}{}
		go func(key string) {
			defer wg.Done()
			defer func() { <-sem }()
			raw, err := d.store.GetObject(ctx, key)
			if err != nil {
				slog.Error("Failed to read audit record for dashboard", slog.String("key", key), slog.Any("error", err))
				mu.Lock()
				incomplete = true
				mu.Unlock()
				return
			}
			var rec AuditRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				slog.Error("Skipping unparsable audit record", slog.String("key", key), slog.Any("error", err))
				return
			}
			mu.Lock()
			rows = append(rows, scanRow{ScanID: rec.ScanID, Filename: rec.Filename, At: rec.FileUploadedAt, ScanMS: rec.ScanMS, Engines: rec.EngineMS})
			mu.Unlock()
		}(key)
	}
	wg.Wait()

	if d.cache != nil && !truncated && !incomplete {
		ttl := openDayCacheTTL
		if final {
			ttl = finalDayCacheTTL
		}
		if raw, err := json.Marshal(rows); err == nil {
			d.cache.Set(ctx, cacheKey, raw, ttl)
		}
	}
	return rows, truncated, nil
}

func sortRows(rows []scanRow, mode string) {
	sort.SliceStable(rows, func(i, j int) bool {
		if mode == "slowest" && rows[i].ScanMS != rows[j].ScanMS {
			return rows[i].ScanMS > rows[j].ScanMS
		}
		return rows[i].At > rows[j].At
	})
}

func paginate(rows []scanRow, page int, size int) ([]scanRow, int) {
	pages := (len(rows) + size - 1) / size
	if pages < 1 {
		pages = 1
	}
	if page < 1 {
		page = 1
	}
	start := (page - 1) * size
	if start >= len(rows) {
		return []scanRow{}, pages
	}
	end := start + size
	if end > len(rows) {
		end = len(rows)
	}
	return rows[start:end], pages
}

func (d *dashboardDeps) dataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant, _ := r.Context().Value(TenantContextKey).(string)
	if tenant == "" {
		writeJSONError(w, "Forbidden", http.StatusForbidden)
		return
	}

	q := r.URL.Query()
	days, err := strconv.Atoi(q.Get("days"))
	if err != nil || (days != 1 && days != 7 && days != 15 && days != 30) {
		writeJSONError(w, "days must be one of 1, 7, 15, 30", http.StatusBadRequest)
		return
	}
	sortMode := q.Get("sort")
	if sortMode == "" {
		sortMode = "newest"
	}
	if sortMode != "newest" && sortMode != "slowest" {
		writeJSONError(w, "sort must be newest or slowest", http.StatusBadRequest)
		return
	}
	page := 1
	if p := q.Get("page"); p != "" {
		if page, err = strconv.Atoi(p); err != nil || page < 1 {
			writeJSONError(w, "page must be a positive integer", http.StatusBadRequest)
			return
		}
	}

	rows, truncated, err := d.queryRows(r.Context(), tenant, days)
	if err != nil {
		slog.Error("Failed to build scan-time dashboard data", slog.String("request_id", requestIDFromContext(r.Context())), slog.String("tenant_id", tenant), slog.Any("error", err))
		writeJSONError(w, "Failed to read scan records", http.StatusInternalServerError)
		return
	}
	if needle := strings.ToLower(strings.TrimSpace(q.Get("q"))); needle != "" {
		filtered := rows[:0]
		for _, row := range rows {
			if strings.Contains(strings.ToLower(row.Filename), needle) {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	sortRows(rows, sortMode)
	pageRows, pages := paginate(rows, page, dashboardPageSize)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"days":      days,
		"total":     len(rows),
		"page":      page,
		"pages":     pages,
		"page_size": dashboardPageSize,
		"truncated": truncated,
		"rows":      pageRows,
	})
}

func dashboardPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	nonce := base64.RawStdEncoding.EncodeToString(nonceBytes)

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	io.WriteString(w, strings.ReplaceAll(dashboardHTML, "{{NONCE}}", nonce))
}

type s3AuditStore struct {
	client *s3.Client
	bucket string
}

func newS3AuditStore(bucket string) (*s3AuditStore, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if os.Getenv("AWS_ENDPOINT_URL") != "" {
			o.UsePathStyle = true
		}
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	return &s3AuditStore{client: client, bucket: bucket}, nil
}

func (s *s3AuditStore) ListKeys(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: aws.String(s.bucket), Prefix: aws.String(prefix)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			keys = append(keys, aws.ToString(obj.Key))
		}
	}
	return keys, nil
}

func (s *s3AuditStore) GetObject(ctx context.Context, key string) ([]byte, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	return io.ReadAll(io.LimitReader(out.Body, 1<<20))
}

type redisDayCache struct{ client *redis.Client }

func (c *redisDayCache) Get(ctx context.Context, key string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	val, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		return nil, false
	}
	return val, true
}

func (c *redisDayCache) Set(ctx context.Context, key string, val []byte, ttl time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := c.client.Set(ctx, key, val, ttl).Err(); err != nil {
		slog.Error("Failed to cache dashboard day", slog.String("key", key), slog.Any("error", err))
	}
}

func registerScanDashboard() {
	id, ok := dashboardPathID(opts)
	if !ok {
		slog.Error("SCAN_DASHBOARD_PATH_ID must be exactly 12 digits; scan-time dashboard disabled")
		return
	}
	bucket := opts["AWS_S3_CLEAN_BUCKET"]
	if bucket == "" {
		slog.Info("Scan-time dashboard disabled: AWS_S3_CLEAN_BUCKET is not configured")
		return
	}
	store, err := newS3AuditStore(bucket)
	if err != nil {
		slog.Error("Scan-time dashboard disabled: could not initialise S3 client", slog.Any("error", err))
		return
	}
	deps := &dashboardDeps{store: store, now: time.Now, maxRows: dashboardMaxRows}
	if redisClient != nil {
		deps.cache = &redisDayCache{client: redisClient}
	}

	base := "/api/v1/" + id
	http.HandleFunc(base, RequestLoggingMiddleware(dashboardPageHandler))
	http.HandleFunc(base+"/data", RequestLoggingMiddleware(AuthMiddleware(deps.dataHandler)))
	slog.Info("Scan-time dashboard enabled")
}
