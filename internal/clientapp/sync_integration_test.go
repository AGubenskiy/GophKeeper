package clientapp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/buildinfo"
	"github.com/AGubenskiy/GophKeeper/internal/clientapi"
	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
	"github.com/AGubenskiy/GophKeeper/internal/domain"
	"github.com/AGubenskiy/GophKeeper/internal/httpapi"
	"github.com/AGubenskiy/GophKeeper/internal/localstore"
	"github.com/AGubenskiy/GophKeeper/internal/syncsvc"
	"github.com/AGubenskiy/GophKeeper/internal/tokens"
)

func TestTwoClientsConvergeThroughSync(t *testing.T) {
	server := newIntegrationSyncServer(t)
	aliceA := newIntegrationClient(t, server, "client-a", "shared-1")
	aliceB := newIntegrationClient(t, server, "client-b")
	seedIntegrationProfile(t, aliceA.dataDir, server.URL, "client-a")
	seedIntegrationProfile(t, aliceB.dataDir, server.URL, "client-b")

	aliceA.run(t, "add", "text", "--title", "Shared note", "--text", "hello from client A")
	out := aliceA.run(t, "sync")
	if !strings.Contains(out, "pushed 1") {
		t.Fatalf("client A sync output = %q, want pushed item", out)
	}

	out = aliceB.run(t, "sync")
	if !strings.Contains(out, "pulled 1") {
		t.Fatalf("client B sync output = %q, want pulled item", out)
	}
	out = aliceB.run(t, "show", "shared-1")
	if !strings.Contains(out, "Title: Shared note") ||
		!strings.Contains(out, "Text:\nhello from client A") {
		t.Fatalf("client B show output = %q, want decrypted item from client A", out)
	}

	profile := integrationProfile(t, aliceB.dataDir)
	if profile.LastRevision != 1 {
		t.Fatalf("client B LastRevision = %d, want 1", profile.LastRevision)
	}
}

func TestTwoClientConflictCanKeepRemote(t *testing.T) {
	server := newIntegrationSyncServer(t)
	aliceA := newIntegrationClient(t, server, "client-a", "shared-1")
	aliceB := newIntegrationClient(t, server, "client-b")
	seedIntegrationProfile(t, aliceA.dataDir, server.URL, "client-a")
	seedIntegrationProfile(t, aliceB.dataDir, server.URL, "client-b")

	aliceA.run(t, "add", "text", "--title", "Shared note", "--text", "initial")
	aliceA.run(t, "sync")
	aliceB.run(t, "sync")

	aliceA.run(t, "edit", "shared-1", "--text", "client A update")
	aliceA.run(t, "sync")
	aliceB.run(t, "edit", "shared-1", "--text", "client B update")
	out := aliceB.run(t, "sync")
	if !strings.Contains(out, "conflicts") {
		t.Fatalf("client B sync output = %q, want conflict summary", out)
	}

	out = aliceB.run(t, "conflict", "list")
	if !strings.Contains(out, "shared-1") {
		t.Fatalf("conflict list output = %q, want shared-1 conflict", out)
	}
	out = aliceB.run(t, "status")
	if !strings.Contains(out, "Conflicts: 1") {
		t.Fatalf("status output = %q, want one conflict", out)
	}

	aliceB.run(t, "conflict", "keep-remote", "shared-1")
	out = aliceB.run(t, "show", "shared-1")
	if !strings.Contains(out, "Text:\nclient A update") ||
		strings.Contains(out, "client B update") {
		t.Fatalf("show output after keep-remote = %q, want server version", out)
	}
	out = aliceB.run(t, "status")
	if strings.Contains(out, "Conflicts:") {
		t.Fatalf("status output after keep-remote = %q, want no conflicts", out)
	}
}

type integrationClient struct {
	dataDir string
	server  *httptest.Server
	itemIDs []string
	nextID  int
}

func newIntegrationClient(t *testing.T, server *httptest.Server, clientID string, itemIDs ...string) *integrationClient {
	t.Helper()

	return &integrationClient{
		dataDir: filepath.Join(t.TempDir(), clientID),
		server:  server,
		itemIDs: append([]string(nil), itemIDs...),
	}
}

func (c *integrationClient) run(t *testing.T, args ...string) string {
	t.Helper()

	var stdout, stderr bytes.Buffer
	deps := dependencies{
		stdout: &stdout,
		stderr: &stderr,
		info:   buildinfo.New("test", "2026-07-03", "abc123"),
		storeFactory: func(path string) (clientStore, error) {
			return localstore.Open(path)
		},
		apiFactory: func(serverURL string) (authAPI, error) {
			return clientapi.New(serverURL, c.server.Client())
		},
		prompter: &fakePrompter{secret: []byte("master-password")},
		deriveAuthSecret: func([]byte, string, string) ([]byte, error) {
			return []byte("derived-secret"), nil
		},
		deriveVaultKey: func([]byte, []byte, cryptoutil.KDFParams) ([]byte, error) {
			return testVaultKey(), nil
		},
		newClientID: func() string {
			return "client-id"
		},
		newItemID: func() string {
			if c.nextID < len(c.itemIDs) {
				id := c.itemIDs[c.nextID]
				c.nextID++
				return id
			}
			c.nextID++
			return fmt.Sprintf("generated-%d", c.nextID)
		},
		now: func() time.Time {
			return time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)
		},
	}

	fullArgs := append([]string{"--data-dir", c.dataDir}, args...)
	code := run(fullArgs, deps)
	if code != 0 {
		t.Fatalf("gk %v exit code = %d, want 0; stderr: %s", args, code, stderr.String())
	}
	return stdout.String()
}

func seedIntegrationProfile(t *testing.T, dataDir, serverURL, clientID string) {
	t.Helper()

	store, err := localstore.Open(filepath.Join(dataDir, defaultDBFileName))
	if err != nil {
		t.Fatalf("Open local store: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	params := cryptoutil.KDFParams{
		Algorithm:   cryptoutil.KDFAlgorithmArgon2id,
		MemoryKiB:   8,
		Iterations:  1,
		Parallelism: 1,
		KeyLength:   cryptoutil.KeyLength32,
	}
	kdfParams, err := cryptoutil.MarshalKDFParams(params)
	if err != nil {
		t.Fatalf("MarshalKDFParams returned error: %v", err)
	}
	now := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)
	if err = store.SaveProfile(context.Background(), localstore.Profile{
		ServerURL: serverURL,
		UserID:    "user-1",
		Login:     "alice",
		ClientID:  clientID,
		AuthSalt:  []byte("auth-salt-123456"),
		VaultSalt: []byte("vault-salt-12345"),
		KDFParams: kdfParams,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("SaveProfile returned error: %v", err)
	}
	if err = store.SaveSession(context.Background(), localstore.Session{
		AccessToken:      "access-token",
		AccessExpiresAt:  now.Add(time.Hour),
		RefreshToken:     "refresh-token",
		RefreshExpiresAt: now.Add(24 * time.Hour),
		UpdatedAt:        now,
	}); err != nil {
		t.Fatalf("SaveSession returned error: %v", err)
	}
}

func integrationProfile(t *testing.T, dataDir string) localstore.Profile {
	t.Helper()

	store, err := localstore.Open(filepath.Join(dataDir, defaultDBFileName))
	if err != nil {
		t.Fatalf("Open local store: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()
	profile, err := store.Profile(context.Background())
	if err != nil {
		t.Fatalf("Profile returned error: %v", err)
	}
	return profile
}

func newIntegrationSyncServer(t *testing.T) *httptest.Server {
	t.Helper()

	repo := newMemorySyncRepo()
	service, err := syncsvc.NewService(repo, repo, func() time.Time {
		return time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	mux := http.NewServeMux()
	httpapi.NewSyncHandler(service, staticIntegrationVerifier{}).RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

type staticIntegrationVerifier struct{}

func (staticIntegrationVerifier) VerifyAccess(tokenText string) (tokens.Principal, error) {
	if strings.TrimSpace(tokenText) == "" {
		return tokens.Principal{}, errors.New("token is required")
	}
	return tokens.Principal{UserID: "user-1", ClientID: "test-client"}, nil
}

type memorySyncRepo struct {
	mu        sync.Mutex
	items     map[string]map[string]domain.VaultItem
	revisions map[string]int64
}

func newMemorySyncRepo() *memorySyncRepo {
	return &memorySyncRepo{
		items:     map[string]map[string]domain.VaultItem{},
		revisions: map[string]int64{},
	}
}

func (r *memorySyncRepo) Upsert(_ context.Context, item domain.VaultItem) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.items[item.UserID] == nil {
		r.items[item.UserID] = map[string]domain.VaultItem{}
	}
	r.items[item.UserID][item.ID] = item.Clone()
	return nil
}

func (r *memorySyncRepo) Find(_ context.Context, userID, itemID string) (domain.VaultItem, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	item, ok := r.items[userID][itemID]
	if !ok {
		return domain.VaultItem{}, domain.ErrNotFound
	}
	return item.Clone(), nil
}

func (r *memorySyncRepo) ListChanged(_ context.Context, userID string, sinceRevision int64, limit int) ([]domain.VaultItem, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	items := make([]domain.VaultItem, 0)
	for _, item := range r.items[userID] {
		if item.ServerRevision > sinceRevision {
			items = append(items, item.Clone())
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].ServerRevision < items[j].ServerRevision
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (r *memorySyncRepo) Get(_ context.Context, userID string) (domain.SyncState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return domain.SyncState{UserID: userID, CurrentRevision: r.revisions[userID]}, nil
}

func (r *memorySyncRepo) Increment(_ context.Context, userID string) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.revisions[userID]++
	return r.revisions[userID], nil
}
