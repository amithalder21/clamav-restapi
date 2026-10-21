package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type memStore struct {
	mu       sync.Mutex
	objects  map[string]string
	getCount map[string]int
	gotKeys  []string
}

func newMemStore() *memStore {
	return &memStore{objects: map[string]string{}, getCount: map[string]int{}}
}

func (m *memStore) ListKeys(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

func (m *memStore) GetObject(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gotKeys = append(m.gotKeys, key)
	m.getCount[key]++
	v, ok := m.objects[key]
	if !ok {
		return nil, fmt.Errorf("no such key %s", key)
	}
	return []byte(v), nil
}

type memCache struct {
	mu   sync.Mutex
	data map[string][]byte
	ttl  map[string]time.Duration
}

func newMemCache() *memCache {
	return &memCache{data: map[string][]byte{}, ttl: map[string]time.Duration{}}
}

func (c *memCache) Get(_ context.Context, key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.data[key]
	return v, ok
}

func (c *memCache) expireShortLived() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, ttl := range c.ttl {
		if ttl <= 5*time.Minute {
			delete(c.data, k)
		}
	}
}

func (c *memCache) Set(_ context.Context, key string, val []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = val
	c.ttl[key] = ttl
}

func record(scanID, filename, uploadedAt string, scanMS int64) string {
	return fmt.Sprintf(`{"scan_id":%q,"request_id":"r","tenant_id":"t","filename":%q,"av-status":"CLEAN","av-signature":"CLEAN","file_s3_key":"k","file_uploaded_at":%q,"file_expires_at":"x","scan_ms":%d,"engine_ms":{"clamav":10,"yara":20,"maldet":%d,"malwarebazaar":5}}`,
		scanID, filename, uploadedAt, scanMS, scanMS)
}

var testNow = time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)

func newDeps(store auditStore, cache dayCache) *dashboardDeps {
	return &dashboardDeps{store: store, cache: cache, now: func() time.Time { return testNow }, maxRows: 1000}
}

func TestDatePrefixesCoversWindowPlusToday(t *testing.T) {
	got := datePrefixes(testNow, 1)
	want := []string{"2026/10/14", "2026/10/13"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("1 day: got %v want %v", got, want)
	}
	got = datePrefixes(testNow, 7)
	if len(got) != 8 || got[0] != "2026/10/14" || got[7] != "2026/10/07" {
		t.Errorf("7 days: got %v", got)
	}
}

func TestQueryRowsReadsOnlyOwnTenantAndWindow(t *testing.T) {
	st := newMemStore()
	st.objects["audit/tenant-a/2026/10/14/s1.json"] = record("s1", "a.pdf", "2026-10-14T08:00:00Z", 500)
	st.objects["audit/tenant-a/2026/10/13/s2.json"] = record("s2", "b.pdf", "2026-10-13T20:00:00Z", 700)
	st.objects["audit/tenant-a/2026/10/13/s3.json"] = record("s3", "old.pdf", "2026-10-13T09:00:00Z", 900)
	st.objects["audit/tenant-b/2026/10/14/x.json"] = record("x", "other.pdf", "2026-10-14T08:00:00Z", 1)
	st.objects["audit/tenant-ab/2026/10/14/y.json"] = record("y", "prefix.pdf", "2026-10-14T08:00:00Z", 1)

	rows, _, err := newDeps(st, nil).queryRows(context.Background(), "tenant-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range rows {
		ids[r.ScanID] = true
	}
	if len(rows) != 2 || !ids["s1"] || !ids["s2"] {
		t.Errorf("expected s1 and s2 only, got %+v", rows)
	}
	for _, k := range st.gotKeys {
		if !strings.HasPrefix(k, "audit/tenant-a/") {
			t.Errorf("read a key outside the tenant prefix: %s", k)
		}
	}
}

func TestQueryRowsMarksUntimedLegacyRecords(t *testing.T) {
	st := newMemStore()
	st.objects["audit/tenant-a/2026/10/14/old.json"] = `{"scan_id":"old","filename":"legacy.pdf","file_uploaded_at":"2026-10-14T08:00:00Z"}`

	rows, _, err := newDeps(st, nil).queryRows(context.Background(), "tenant-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Engines != nil {
		t.Fatalf("legacy record should be listed with no engine timings, got %+v", rows)
	}
}

func TestQueryRowsCachesFinishedDaysButRereadsToday(t *testing.T) {
	st := newMemStore()
	past := "audit/tenant-a/2026/10/13/p.json"
	today := "audit/tenant-a/2026/10/14/t.json"
	st.objects[past] = record("p", "p.pdf", "2026-10-13T20:00:00Z", 100)
	st.objects[today] = record("t", "t.pdf", "2026-10-14T08:00:00Z", 100)
	cache := newMemCache()
	d := newDeps(st, cache)

	for i := 0; i < 2; i++ {
		if _, _, err := d.queryRows(context.Background(), "tenant-a", 1); err != nil {
			t.Fatal(err)
		}
		cache.expireShortLived()
	}
	if st.getCount[past] != 1 {
		t.Errorf("finished day should be read once, was read %d times", st.getCount[past])
	}
	if st.getCount[today] != 2 {
		t.Errorf("today should be re-read once its short cache entry expires, was read %d times", st.getCount[today])
	}
	if cache.ttl["dash:v1:tenant-a:2026/10/13"] < time.Hour {
		t.Errorf("finished day TTL too short: %v", cache.ttl["dash:v1:tenant-a:2026/10/13"])
	}
	if ttl := cache.ttl["dash:v1:tenant-a:2026/10/14"]; ttl <= 0 || ttl > 5*time.Minute {
		t.Errorf("today TTL should be short, got %v", ttl)
	}
}

func TestQueryRowsDoesNotTreatJustEndedDayAsFinal(t *testing.T) {
	st := newMemStore()
	st.objects["audit/tenant-a/2026/10/13/p.json"] = record("p", "p.pdf", "2026-10-13T23:59:58Z", 100)
	cache := newMemCache()
	d := newDeps(st, cache)
	d.now = func() time.Time { return time.Date(2026, 10, 14, 0, 5, 0, 0, time.UTC) }

	if _, _, err := d.queryRows(context.Background(), "tenant-a", 1); err != nil {
		t.Fatal(err)
	}
	if ttl := cache.ttl["dash:v1:tenant-a:2026/10/13"]; ttl > 5*time.Minute {
		t.Errorf("a day that ended 5 minutes ago can still receive late records, TTL = %v", ttl)
	}
}

func TestQueryRowsCapsAndFlagsTruncation(t *testing.T) {
	st := newMemStore()
	for i := 0; i < 5; i++ {
		st.objects[fmt.Sprintf("audit/tenant-a/2026/10/14/s%d.json", i)] = record(fmt.Sprintf("s%d", i), "f.pdf", "2026-10-14T08:00:00Z", 100)
	}
	d := newDeps(st, nil)
	d.maxRows = 3

	rows, truncated, err := d.queryRows(context.Background(), "tenant-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || !truncated {
		t.Errorf("want 3 rows and truncated=true, got %d rows truncated=%v", len(rows), truncated)
	}
}

func TestSortAndPaginate(t *testing.T) {
	rows := []scanRow{
		{ScanID: "a", At: "2026-10-14T01:00:00Z", ScanMS: 300},
		{ScanID: "b", At: "2026-10-14T03:00:00Z", ScanMS: 100},
		{ScanID: "c", At: "2026-10-14T02:00:00Z", ScanMS: 900},
		{ScanID: "d", At: "2026-10-14T05:00:00Z", ScanMS: 200},
		{ScanID: "e", At: "2026-10-14T04:00:00Z", ScanMS: 50},
	}
	sortRows(rows, "slowest")
	if rows[0].ScanID != "c" || rows[4].ScanID != "e" {
		t.Errorf("slowest order wrong: %v", ids(rows))
	}
	sortRows(rows, "newest")
	if rows[0].ScanID != "d" || rows[4].ScanID != "a" {
		t.Errorf("newest order wrong: %v", ids(rows))
	}
	page, pages := paginate(rows, 3, 2)
	if pages != 3 || len(page) != 1 {
		t.Errorf("page 3 of 5 rows at size 2: got %d rows, %d pages", len(page), pages)
	}
	if page, _ := paginate(rows, 99, 2); len(page) != 0 {
		t.Errorf("page past the end should be empty, got %d rows", len(page))
	}
}

func ids(rows []scanRow) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r.ScanID)
	}
	return out
}

func dataRequest(query string, tenant string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/824339653470/data?"+query, nil)
	if tenant != "" {
		req = req.WithContext(context.WithValue(req.Context(), TenantContextKey, tenant))
	}
	return req
}

func TestDataHandlerReturnsTenantRows(t *testing.T) {
	st := newMemStore()
	st.objects["audit/tenant-a/2026/10/14/s1.json"] = record("s1", "Invoice.pdf", "2026-10-14T08:00:00Z", 500)
	st.objects["audit/tenant-a/2026/10/14/s2.json"] = record("s2", "packing.xlsx", "2026-10-14T09:00:00Z", 700)
	d := newDeps(st, nil)

	rec := httptest.NewRecorder()
	d.dataHandler(rec, dataRequest("days=7&q=invoice", "tenant-a"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Days  int `json:"days"`
		Total int `json:"total"`
		Rows  []struct {
			ScanID   string `json:"scan_id"`
			Filename string `json:"filename"`
			ScanMS   int64  `json:"scan_ms"`
			Engines  struct {
				Maldet int64 `json:"maldet"`
			} `json:"engine_ms"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Days != 7 || resp.Total != 1 || len(resp.Rows) != 1 || resp.Rows[0].ScanID != "s1" || resp.Rows[0].ScanMS != 500 || resp.Rows[0].Engines.Maldet != 500 {
		t.Errorf("unexpected response: %s", rec.Body.String())
	}
}

func TestDataHandlerRejectsBadInput(t *testing.T) {
	d := newDeps(newMemStore(), nil)
	for name, tc := range map[string]struct {
		query, tenant string
		want          int
	}{
		"unsupported range": {"days=3", "tenant-a", http.StatusBadRequest},
		"missing range":     {"", "tenant-a", http.StatusBadRequest},
		"bad sort":          {"days=7&sort=oldest", "tenant-a", http.StatusBadRequest},
		"no tenant":         {"days=7", "", http.StatusForbidden},
	} {
		rec := httptest.NewRecorder()
		d.dataHandler(rec, dataRequest(tc.query, tc.tenant))
		if rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d", name, rec.Code, tc.want)
		}
	}
}

func TestDashboardPathID(t *testing.T) {
	if id, ok := dashboardPathID(map[string]string{}); !ok || id != defaultDashboardPathID {
		t.Errorf("unset should fall back to the default, got %q ok=%v", id, ok)
	}
	if id, ok := dashboardPathID(map[string]string{"SCAN_DASHBOARD_PATH_ID": "111122223333"}); !ok || id != "111122223333" {
		t.Errorf("valid override rejected: %q ok=%v", id, ok)
	}
	for _, bad := range []string{"12345", "12345678901a", "1234567890123", "../admin00000"} {
		if _, ok := dashboardPathID(map[string]string{"SCAN_DASHBOARD_PATH_ID": bad}); ok {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestDashboardPageIsLockedDown(t *testing.T) {
	rec := httptest.NewRecorder()
	dashboardPageHandler(rec, httptest.NewRequest(http.MethodGet, "/api/v1/824339653470", nil))

	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("status %d content-type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("weak CSP: %q", csp)
	}
	i := strings.Index(csp, "'nonce-")
	if i < 0 {
		t.Fatalf("CSP has no nonce: %q", csp)
	}
	nonce := csp[i+len("'nonce-") : i+len("'nonce-")+strings.Index(csp[i+len("'nonce-"):], "'")]
	if nonce == "" || !strings.Contains(body, `nonce="`+nonce+`"`) {
		t.Errorf("page does not carry the CSP nonce %q", nonce)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
		t.Errorf("missing nosniff/no-store headers: %v", rec.Header())
	}
	if strings.Contains(body, "innerHTML") {
		t.Error("page must render file names as text, never via innerHTML")
	}
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
		t.Error("page must not reference external resources")
	}

	rec2 := httptest.NewRecorder()
	dashboardPageHandler(rec2, httptest.NewRequest(http.MethodPost, "/api/v1/824339653470", nil))
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST should be 405, got %d", rec2.Code)
	}
}

func TestS3AuditStoreListsAndReadsObjects(t *testing.T) {
	s3 := newFakeS3(t)
	s3.objects["clean-bucket/audit/tenant-a/2026/10/14/s1.json"] = []byte(`{"scan_id":"s1"}`)
	s3.objects["clean-bucket/audit/tenant-ab/2026/10/14/s9.json"] = []byte(`{"scan_id":"s9"}`)

	store, err := newS3AuditStore("clean-bucket")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := store.ListKeys(context.Background(), "audit/tenant-a/2026/10/14/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "audit/tenant-a/2026/10/14/s1.json" {
		t.Fatalf("unexpected keys: %v", keys)
	}
	body, err := store.GetObject(context.Background(), keys[0])
	if err != nil || string(body) != `{"scan_id":"s1"}` {
		t.Errorf("unexpected object: %q err=%v", body, err)
	}
}

func TestRegisteredRoutesPageIsOpenButDataRequiresAuth(t *testing.T) {
	newFakeS3(t)
	opts = map[string]string{"AWS_S3_CLEAN_BUCKET": "clean-bucket"}
	jwks = nil

	registerScanDashboard()

	page := httptest.NewRecorder()
	http.DefaultServeMux.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/api/v1/"+defaultDashboardPathID, nil))
	if page.Code != http.StatusOK {
		t.Errorf("page route: status %d", page.Code)
	}

	data := httptest.NewRecorder()
	http.DefaultServeMux.ServeHTTP(data, httptest.NewRequest(http.MethodGet, "/api/v1/"+defaultDashboardPathID+"/data?days=7", nil))
	if data.Code != http.StatusForbidden && data.Code != http.StatusUnauthorized {
		t.Errorf("data route without a token: status %d, want 401/403; body %s", data.Code, data.Body.String())
	}
	if !strings.Contains(data.Body.String(), "COGNITO_JWKS_URL") {
		t.Errorf("data route must be rejected by AuthMiddleware itself, got: %s", data.Body.String())
	}
	if strings.Contains(data.Body.String(), `"rows"`) {
		t.Error("data route leaked rows without authentication")
	}

	guessed := httptest.NewRecorder()
	http.DefaultServeMux.ServeHTTP(guessed, httptest.NewRequest(http.MethodGet, "/api/v1/admin/dashboard", nil))
	if strings.Contains(guessed.Body.String(), "Malware scan time") {
		t.Error("dashboard must not be served on a guessable path")
	}
}
