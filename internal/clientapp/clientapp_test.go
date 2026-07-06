package clientapp

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AGubenskiy/GophKeeper/internal/buildinfo"
	"github.com/AGubenskiy/GophKeeper/internal/clientapi"
	"github.com/AGubenskiy/GophKeeper/internal/cryptoutil"
	"github.com/AGubenskiy/GophKeeper/internal/localstore"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run([]string{"version"}, &stdout, &stderr, buildinfo.New("1.0.0", "2026-07-02", "abc123"))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Build version: 1.0.0") {
		t.Fatalf("stdout = %q, want build version", stdout.String())
	}
}

func TestRegisterSavesProfileAndSession(t *testing.T) {
	deps, store, api, stdout, stderr := newTestDependencies()

	code := run([]string{"register", "--server", "http://server.local", "--login", "alice"}, deps)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if api.registerRequest.Login != "alice" || api.registerRequest.ClientID != "client-1" {
		t.Fatalf("register request = %+v, want login/client", api.registerRequest)
	}
	if decoded := decodeBase64(t, api.registerRequest.AuthSecret); string(decoded) != "derived-secret" {
		t.Fatalf("auth secret = %q, want derived-secret", decoded)
	}
	if !store.hasProfile || store.profile.Login != "alice" || store.profile.ClientID != "client-1" {
		t.Fatalf("stored profile = %+v, want registered profile", store.profile)
	}
	if !store.hasSession || store.session.RefreshToken != "refresh-token" {
		t.Fatalf("stored session = %+v, want refresh token", store.session)
	}
	if !strings.Contains(stdout.String(), "Registered alice") {
		t.Fatalf("stdout = %q, want registration message", stdout.String())
	}
}

func TestLoginUsesExistingProfileDefaults(t *testing.T) {
	deps, store, api, stdout, stderr := newTestDependencies()
	store.profile = localstore.Profile{
		ServerURL: "http://server.local",
		UserID:    "user-1",
		Login:     "alice",
		ClientID:  "existing-client",
		AuthSalt:  []byte("auth-salt"),
		VaultSalt: []byte("vault-salt"),
		KDFParams: []byte(`{"algorithm":"argon2id"}`),
	}
	store.hasProfile = true

	code := run([]string{"login"}, deps)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if api.loginRequest.Login != "alice" || api.loginRequest.ClientID != "existing-client" {
		t.Fatalf("login request = %+v, want existing profile login/client", api.loginRequest)
	}
	if !store.hasSession {
		t.Fatal("login did not save session")
	}
	if !strings.Contains(stdout.String(), "Logged in as alice") {
		t.Fatalf("stdout = %q, want login message", stdout.String())
	}
}

func TestRunFormatsAPIError(t *testing.T) {
	deps, store, api, _, stderr := newTestDependencies()
	store.profile = testProfile(t)
	store.hasProfile = true
	api.loginErr = &clientapi.Error{
		StatusCode: http.StatusUnauthorized,
		Code:       "invalid_credentials",
		Message:    "invalid credentials",
		RequestID:  "req-1",
	}

	code := run([]string{"login"}, deps)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "Error: invalid login or master password (request id: req-1)") {
		t.Fatalf("stderr = %q, want formatted API error", stderr.String())
	}
}

func TestLogoutRevokesAndClearsSession(t *testing.T) {
	deps, store, api, _, stderr := newTestDependencies()
	store.profile = localstore.Profile{ServerURL: "http://server.local", UserID: "user-1", Login: "alice", ClientID: "client-1", AuthSalt: []byte("a"), VaultSalt: []byte("v"), KDFParams: []byte("{}")}
	store.session = localstore.Session{
		AccessToken:      "access-token",
		AccessExpiresAt:  time.Now().Add(time.Minute),
		RefreshToken:     "refresh-token",
		RefreshExpiresAt: time.Now().Add(time.Hour),
	}
	store.hasProfile = true
	store.hasSession = true

	code := run([]string{"logout"}, deps)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if api.logoutToken != "refresh-token" {
		t.Fatalf("logout token = %q, want refresh-token", api.logoutToken)
	}
	if store.hasSession {
		t.Fatal("logout did not clear session")
	}
}

func TestLogoutWithoutProfileReportsLoginHint(t *testing.T) {
	deps, _, _, _, stderr := newTestDependencies()

	code := run([]string{"logout"}, deps)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "Error: local profile not found; run login first") {
		t.Fatalf("stderr = %q, want login hint", stderr.String())
	}
}

func TestStatusPrintsEmptyAndPopulatedState(t *testing.T) {
	deps, store, _, stdout, stderr := newTestDependencies()

	code := run([]string{"status"}, deps)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Profile: none") {
		t.Fatalf("stdout = %q, want empty profile status", stdout.String())
	}

	stdout.Reset()
	store.status = localstore.Status{
		HasProfile:   true,
		HasSession:   true,
		ServerURL:    "http://server.local",
		UserID:       "user-1",
		Login:        "alice",
		ClientID:     "client-1",
		LastRevision: 3,
		ItemCount:    2,
		DirtyCount:   1,
	}
	code = run([]string{"status"}, deps)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Profile: alice @ http://server.local") ||
		!strings.Contains(stdout.String(), "Local items: 2 (dirty: 1)") {
		t.Fatalf("stdout = %q, want populated status", stdout.String())
	}
}

func TestAddListShowEditAndDeletePasswordItem(t *testing.T) {
	deps, store, _, stdout, stderr := newTestDependencies()
	store.profile = testProfile(t)
	store.hasProfile = true
	deps.prompter = &fakePrompter{secrets: [][]byte{
		[]byte("password-1"),
		[]byte("master-password"),
		[]byte("master-password"),
		[]byte("master-password"),
		[]byte("master-password"),
		[]byte("password-2"),
		[]byte("master-password"),
	}}

	code := run([]string{"add", "password", "--title", "GitHub", "--login", "alice", "--meta", "url=https://github.com"}, deps)
	if code != 0 {
		t.Fatalf("add exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Added password item-1") {
		t.Fatalf("stdout = %q, want added item message", stdout.String())
	}
	if store.items["item-1"].DirtyState != localstore.DirtyStateUpsert {
		t.Fatalf("stored item = %+v, want dirty upsert", store.items["item-1"])
	}

	stdout.Reset()
	code = run([]string{"list"}, deps)
	if code != 0 {
		t.Fatalf("list exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "GitHub") || strings.Contains(stdout.String(), "password-1") {
		t.Fatalf("list stdout = %q, want title without password", stdout.String())
	}

	stdout.Reset()
	code = run([]string{"show", "item-1"}, deps)
	if code != 0 {
		t.Fatalf("show exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Password: password-1") ||
		!strings.Contains(stdout.String(), "url: https://github.com") {
		t.Fatalf("show stdout = %q, want decrypted password and metadata", stdout.String())
	}

	stdout.Reset()
	code = run([]string{"edit", "item-1", "--login", "bob", "--password", "--meta", "env=prod"}, deps)
	if code != 0 {
		t.Fatalf("edit exit code = %d, want 0; stderr: %s", code, stderr.String())
	}

	stdout.Reset()
	code = run([]string{"show", "item-1"}, deps)
	if code != 0 {
		t.Fatalf("show after edit exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Login: bob") ||
		!strings.Contains(stdout.String(), "Password: password-2") ||
		!strings.Contains(stdout.String(), "env: prod") {
		t.Fatalf("show stdout = %q, want edited fields", stdout.String())
	}

	code = run([]string{"delete", "item-1"}, deps)
	if code != 0 {
		t.Fatalf("delete exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	deleted := store.items["item-1"]
	if deleted.DeletedAt == nil || deleted.DirtyState != localstore.DirtyStateDelete {
		t.Fatalf("deleted item = %+v, want tombstone", deleted)
	}
}

func TestDeleteMissingItemReportsItemID(t *testing.T) {
	deps, _, _, _, stderr := newTestDependencies()

	code := run([]string{"delete", "missing"}, deps)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "Error: item \"missing\" not found") {
		t.Fatalf("stderr = %q, want item id", stderr.String())
	}
}

func TestAddAndShowTextCardAndFileItems(t *testing.T) {
	deps, store, _, stdout, stderr := newTestDependencies()
	store.profile = testProfile(t)
	store.hasProfile = true
	deps.prompter = &fakePrompter{secret: []byte("master-password")}
	ids := []string{"text-1", "card-1", "file-1"}
	nextID := 0
	deps.newItemID = func() string {
		id := ids[nextID]
		nextID++
		return id
	}

	filePath := filepath.Join(t.TempDir(), "license.txt")
	if err := os.WriteFile(filePath, []byte("file-content"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	tests := [][]string{
		{"add", "text", "--title", "Note", "--text", "hello", "--meta", "scope=demo"},
		{"add", "card", "--title", "Visa", "--number", "4111111111111111", "--holder", "Alice", "--expiry", "12/30"},
		{"add", "file", "--title", "License", "--path", filePath},
	}
	for _, args := range tests {
		stdout.Reset()
		if code := run(args, deps); code != 0 {
			t.Fatalf("%v exit code = %d, want 0; stderr: %s", args, code, stderr.String())
		}
	}

	stdout.Reset()
	if code := run([]string{"show", "text-1"}, deps); code != 0 {
		t.Fatalf("show text exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Text:\nhello") ||
		!strings.Contains(stdout.String(), "scope: demo") {
		t.Fatalf("text stdout = %q, want decrypted text and metadata", stdout.String())
	}

	stdout.Reset()
	if code := run([]string{"show", "card-1"}, deps); code != 0 {
		t.Fatalf("show card exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "4111111111111111") ||
		!strings.Contains(stdout.String(), "**** **** **** 1111") {
		t.Fatalf("card stdout = %q, want masked card number", stdout.String())
	}

	exportPath := filepath.Join(t.TempDir(), "exported.txt")
	stdout.Reset()
	if code := run([]string{"show", "file-1", "--export", exportPath}, deps); code != 0 {
		t.Fatalf("show file exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	exported, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(exported) != "file-content" || !strings.Contains(stdout.String(), "Size: 12 bytes") {
		t.Fatalf("file stdout = %q exported = %q, want exported file content", stdout.String(), exported)
	}
}

func TestAddFileRejectsTooLargeFile(t *testing.T) {
	deps, _, _, _, stderr := newTestDependencies()
	oldMax := maxFileItemBytes
	maxFileItemBytes = 4
	defer func() {
		maxFileItemBytes = oldMax
	}()

	filePath := filepath.Join(t.TempDir(), "large.bin")
	if err := os.WriteFile(filePath, []byte("12345"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	code := run([]string{"add", "file", "--title", "Large", "--path", filePath}, deps)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "file is too large") {
		t.Fatalf("stderr = %q, want file size error", stderr.String())
	}
}

func TestSyncPushesDirtyItemsPullsChangesAndUpdatesRevision(t *testing.T) {
	deps, store, api, stdout, stderr := newTestDependencies()
	store.profile = testProfile(t)
	store.profile.LastRevision = 2
	store.session = localstore.Session{
		AccessToken:      "access-token",
		AccessExpiresAt:  time.Now().Add(time.Minute),
		RefreshToken:     "refresh-token",
		RefreshExpiresAt: time.Now().Add(time.Hour),
	}
	store.hasProfile = true
	store.hasSession = true
	store.items["local-1"] = localstore.Item{
		ID:               "local-1",
		ServerRevision:   2,
		EncryptedPayload: []byte("local-ciphertext"),
		PayloadNonce:     []byte("local-nonce"),
		PayloadVersion:   1,
		DirtyState:       localstore.DirtyStateUpsert,
		UpdatedAt:        time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC),
	}
	api.pushResponse = clientapi.PushResponse{
		Applied: []clientapi.SyncItem{
			{
				ID:               "local-1",
				ServerRevision:   3,
				EncryptedPayload: base64.StdEncoding.EncodeToString([]byte("server-local-ciphertext")),
				PayloadNonce:     base64.StdEncoding.EncodeToString([]byte("server-local-nonce")),
				PayloadVersion:   1,
				UpdatedAt:        time.Date(2026, 7, 3, 10, 1, 0, 0, time.UTC),
			},
		},
		CurrentRevision: 3,
	}
	api.changes = clientapi.Changes{
		Items: []clientapi.SyncItem{
			{
				ID:               "remote-1",
				ServerRevision:   4,
				EncryptedPayload: base64.StdEncoding.EncodeToString([]byte("remote-ciphertext")),
				PayloadNonce:     base64.StdEncoding.EncodeToString([]byte("remote-nonce")),
				PayloadVersion:   1,
				UpdatedAt:        time.Date(2026, 7, 3, 10, 2, 0, 0, time.UTC),
			},
		},
		CurrentRevision: 4,
	}

	code := run([]string{"sync"}, deps)
	if code != 0 {
		t.Fatalf("sync exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if api.pushToken != "access-token" || api.pullSince != 2 {
		t.Fatalf("sync API token/since = %q/%d, want access-token/2", api.pushToken, api.pullSince)
	}
	if got := api.pushed[0]; got.ID != "local-1" || got.BaseRevision != 2 {
		t.Fatalf("pushed item = %+v, want local dirty item", got)
	}
	if store.profile.LastRevision != 4 {
		t.Fatalf("LastRevision = %d, want 4", store.profile.LastRevision)
	}
	if store.items["local-1"].DirtyState != localstore.DirtyStateClean || store.items["local-1"].ServerRevision != 3 {
		t.Fatalf("local item = %+v, want clean server revision 3", store.items["local-1"])
	}
	if store.items["remote-1"].ServerRevision != 4 {
		t.Fatalf("remote item = %+v, want pulled remote item", store.items["remote-1"])
	}
	if !strings.Contains(stdout.String(), "Sync complete: pushed 1, pulled 1, conflicts 0") {
		t.Fatalf("stdout = %q, want sync summary", stdout.String())
	}
}

func TestSyncPullsUntilCurrentRevisionIsReached(t *testing.T) {
	deps, store, api, stdout, stderr := newTestDependencies()
	store.profile = testProfile(t)
	store.session = localstore.Session{
		AccessToken:      "access-token",
		AccessExpiresAt:  time.Now().Add(time.Minute),
		RefreshToken:     "refresh-token",
		RefreshExpiresAt: time.Now().Add(time.Hour),
	}
	store.hasProfile = true
	store.hasSession = true
	api.pullChanges = []clientapi.Changes{
		{
			Items: []clientapi.SyncItem{
				testSyncItem("remote-1", 1),
				testSyncItem("remote-2", 2),
			},
			CurrentRevision: 3,
		},
		{
			Items: []clientapi.SyncItem{
				testSyncItem("remote-3", 3),
			},
			CurrentRevision: 3,
		},
	}

	code := run([]string{"sync"}, deps)
	if code != 0 {
		t.Fatalf("sync exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if len(api.pullSinceValues) != 2 || api.pullSinceValues[0] != 0 || api.pullSinceValues[1] != 2 {
		t.Fatalf("pull since values = %v, want [0 2]", api.pullSinceValues)
	}
	if store.profile.LastRevision != 3 {
		t.Fatalf("LastRevision = %d, want 3", store.profile.LastRevision)
	}
	if len(store.items) != 3 {
		t.Fatalf("stored item count = %d, want 3", len(store.items))
	}
	if !strings.Contains(stdout.String(), "Sync complete: pushed 0, pulled 3, conflicts 0") {
		t.Fatalf("stdout = %q, want all pulled items in summary", stdout.String())
	}
}

func TestSyncRefreshesExpiredAccessTokenBeforeRequests(t *testing.T) {
	deps, store, api, _, stderr := newTestDependencies()
	now := deps.now()
	store.profile = testProfile(t)
	store.profile.LastRevision = 2
	store.session = localstore.Session{
		AccessToken:      "expired-access-token",
		AccessExpiresAt:  now.Add(-time.Minute),
		RefreshToken:     "old-refresh-token",
		RefreshExpiresAt: now.Add(time.Hour),
	}
	store.hasProfile = true
	store.hasSession = true
	store.items["local-1"] = localstore.Item{
		ID:               "local-1",
		ServerRevision:   2,
		EncryptedPayload: []byte("local-ciphertext"),
		PayloadNonce:     []byte("local-nonce"),
		PayloadVersion:   1,
		DirtyState:       localstore.DirtyStateUpsert,
		UpdatedAt:        now,
	}
	api.session = clientapi.Session{
		AccessToken:      "fresh-access-token",
		AccessExpiresAt:  now.Add(time.Minute),
		RefreshToken:     "new-refresh-token",
		RefreshExpiresAt: now.Add(time.Hour),
	}
	api.pushResponse = clientapi.PushResponse{
		Applied: []clientapi.SyncItem{
			{
				ID:               "local-1",
				ServerRevision:   3,
				EncryptedPayload: base64.StdEncoding.EncodeToString([]byte("server-ciphertext")),
				PayloadNonce:     base64.StdEncoding.EncodeToString([]byte("server-nonce")),
				PayloadVersion:   1,
				UpdatedAt:        now.Add(time.Second),
			},
		},
		CurrentRevision: 3,
	}
	api.changes = clientapi.Changes{CurrentRevision: 3}

	code := run([]string{"sync"}, deps)
	if code != 0 {
		t.Fatalf("sync exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if api.refreshToken != "old-refresh-token" || api.refreshCount != 1 {
		t.Fatalf("refresh token/count = %q/%d, want old-refresh-token/1", api.refreshToken, api.refreshCount)
	}
	if api.pushToken != "fresh-access-token" || api.pullToken != "fresh-access-token" {
		t.Fatalf("sync tokens = %q/%q, want fresh-access-token", api.pushToken, api.pullToken)
	}
	if store.session.AccessToken != "fresh-access-token" || store.session.RefreshToken != "new-refresh-token" {
		t.Fatalf("stored session = %+v, want refreshed tokens", store.session)
	}
}

func TestSyncRetriesUnauthorizedPushAfterRefreshingSession(t *testing.T) {
	deps, store, api, _, stderr := newTestDependencies()
	now := deps.now()
	store.profile = testProfile(t)
	store.profile.LastRevision = 2
	store.session = localstore.Session{
		AccessToken:      "stale-access-token",
		AccessExpiresAt:  now.Add(time.Hour),
		RefreshToken:     "refresh-token",
		RefreshExpiresAt: now.Add(time.Hour),
	}
	store.hasProfile = true
	store.hasSession = true
	store.items["local-1"] = localstore.Item{
		ID:               "local-1",
		ServerRevision:   2,
		EncryptedPayload: []byte("local-ciphertext"),
		PayloadNonce:     []byte("local-nonce"),
		PayloadVersion:   1,
		DirtyState:       localstore.DirtyStateUpsert,
		UpdatedAt:        now,
	}
	api.session = clientapi.Session{
		AccessToken:      "fresh-access-token",
		AccessExpiresAt:  now.Add(time.Hour),
		RefreshToken:     "rotated-refresh-token",
		RefreshExpiresAt: now.Add(2 * time.Hour),
	}
	api.pushErrors = []error{
		&clientapi.Error{StatusCode: http.StatusUnauthorized, Code: "unauthorized", Message: "authorization bearer token is invalid"},
	}
	api.pushResponse = clientapi.PushResponse{
		Applied: []clientapi.SyncItem{
			{
				ID:               "local-1",
				ServerRevision:   3,
				EncryptedPayload: base64.StdEncoding.EncodeToString([]byte("server-ciphertext")),
				PayloadNonce:     base64.StdEncoding.EncodeToString([]byte("server-nonce")),
				PayloadVersion:   1,
				UpdatedAt:        now.Add(time.Second),
			},
		},
		CurrentRevision: 3,
	}
	api.changes = clientapi.Changes{CurrentRevision: 3}

	code := run([]string{"sync"}, deps)
	if code != 0 {
		t.Fatalf("sync exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if api.refreshCount != 1 {
		t.Fatalf("refresh count = %d, want 1", api.refreshCount)
	}
	if len(api.pushTokens) != 2 || api.pushTokens[0] != "stale-access-token" || api.pushTokens[1] != "fresh-access-token" {
		t.Fatalf("push tokens = %v, want stale then fresh", api.pushTokens)
	}
	if api.pullToken != "fresh-access-token" {
		t.Fatalf("pull token = %q, want fresh-access-token", api.pullToken)
	}
}

func TestSyncConflictListKeepLocalAndKeepRemote(t *testing.T) {
	deps, store, api, stdout, stderr := newTestDependencies()
	store.profile = testProfile(t)
	store.profile.LastRevision = 4
	store.session = localstore.Session{
		AccessToken:      "access-token",
		AccessExpiresAt:  time.Now().Add(time.Minute),
		RefreshToken:     "refresh-token",
		RefreshExpiresAt: time.Now().Add(time.Hour),
	}
	store.hasProfile = true
	store.hasSession = true
	store.items["item-1"] = localstore.Item{
		ID:               "item-1",
		ServerRevision:   2,
		EncryptedPayload: []byte("local-ciphertext"),
		PayloadNonce:     []byte("local-nonce"),
		PayloadVersion:   1,
		DirtyState:       localstore.DirtyStateUpsert,
		UpdatedAt:        time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC),
	}
	remote := clientapi.SyncItem{
		ID:               "item-1",
		ServerRevision:   5,
		EncryptedPayload: base64.StdEncoding.EncodeToString([]byte("remote-ciphertext")),
		PayloadNonce:     base64.StdEncoding.EncodeToString([]byte("remote-nonce")),
		PayloadVersion:   1,
		UpdatedAt:        time.Date(2026, 7, 3, 10, 2, 0, 0, time.UTC),
	}
	api.pushResponse = clientapi.PushResponse{
		Conflicts: []clientapi.SyncConflict{
			{
				ID:             "item-1",
				BaseRevision:   2,
				ServerRevision: 5,
				Reason:         "revision_mismatch",
				Remote:         &remote,
			},
		},
		CurrentRevision: 5,
	}
	api.changes = clientapi.Changes{CurrentRevision: 5}
	api.changes.Items = []clientapi.SyncItem{remote}

	code := run([]string{"sync"}, deps)
	if code != 0 {
		t.Fatalf("sync exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if store.items["item-1"].DirtyState != localstore.DirtyStateConflict {
		t.Fatalf("item = %+v, want conflict state", store.items["item-1"])
	}
	if !strings.Contains(stdout.String(), "Resolve conflicts with: gk conflict list") {
		t.Fatalf("sync stdout = %q, want conflict resolution hint", stdout.String())
	}
	if !strings.Contains(stdout.String(), "conflicts 1") {
		t.Fatalf("sync stdout = %q, want one logical conflict", stdout.String())
	}
	if got := store.conflicts["item-1"]; got.RemoteItem == nil || got.RemoteItem.ServerRevision != 5 {
		t.Fatalf("conflict = %+v, want remote revision 5", got)
	}

	stdout.Reset()
	code = run([]string{"conflict", "list"}, deps)
	if code != 0 {
		t.Fatalf("conflict list exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "item-1") || !strings.Contains(stdout.String(), "revision_mismatch") {
		t.Fatalf("conflict list stdout = %q, want stored conflict", stdout.String())
	}

	stdout.Reset()
	code = run([]string{"conflict", "keep-local", "item-1"}, deps)
	if code != 0 {
		t.Fatalf("keep-local exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	local := store.items["item-1"]
	if local.DirtyState != localstore.DirtyStateUpsert || local.ServerRevision != 5 {
		t.Fatalf("local item = %+v, want upsert based on remote revision 5", local)
	}
	if _, ok := store.conflicts["item-1"]; ok {
		t.Fatal("keep-local did not clear conflict")
	}

	local.DirtyState = localstore.DirtyStateConflict
	local.ServerRevision = 2
	store.items["item-1"] = local
	remoteItem, err := localItemFromSync(remote, localstore.DirtyStateClean)
	if err != nil {
		t.Fatalf("localItemFromSync returned error: %v", err)
	}
	store.conflicts["item-1"] = localstore.Conflict{
		ItemID:        "item-1",
		Reason:        "revision_mismatch",
		LocalRevision: 2,
		RemoteItem:    &remoteItem,
		UpdatedAt:     time.Date(2026, 7, 3, 10, 3, 0, 0, time.UTC),
	}

	stdout.Reset()
	code = run([]string{"conflict", "keep-remote", "item-1"}, deps)
	if code != 0 {
		t.Fatalf("keep-remote exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	keptRemote := store.items["item-1"]
	if keptRemote.DirtyState != localstore.DirtyStateClean ||
		keptRemote.ServerRevision != 5 ||
		string(keptRemote.EncryptedPayload) != "remote-ciphertext" {
		t.Fatalf("remote item = %+v, want clean remote value", keptRemote)
	}
	if _, ok := store.conflicts["item-1"]; ok {
		t.Fatal("keep-remote did not clear conflict")
	}
}

func TestConflictMissingReportsConflictID(t *testing.T) {
	deps, _, _, _, stderr := newTestDependencies()

	code := run([]string{"conflict", "keep-remote", "missing"}, deps)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "Error: conflict for item \"missing\" not found; run `gk conflict list`") {
		t.Fatalf("stderr = %q, want conflict id and hint", stderr.String())
	}
}

func TestRegisterRequiresFlags(t *testing.T) {
	deps, _, _, _, _ := newTestDependencies()

	code := run([]string{"register", "--server", "http://server.local"}, deps)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func newTestDependencies() (dependencies, *fakeStore, *fakeAPI, *bytes.Buffer, *bytes.Buffer) {
	store := &fakeStore{
		items:     map[string]localstore.Item{},
		conflicts: map[string]localstore.Conflict{},
	}
	api := &fakeAPI{session: testSession()}
	var stdout, stderr bytes.Buffer

	deps := dependencies{
		stdout: &stdout,
		stderr: &stderr,
		info:   buildinfo.New("test", "2026-07-03", "abc123"),
		storeFactory: func(string) (clientStore, error) {
			return store, nil
		},
		apiFactory: func(string) (authAPI, error) {
			return api, nil
		},
		prompter: &fakePrompter{secret: []byte("master-password")},
		deriveAuthSecret: func([]byte, string, string) ([]byte, error) {
			return []byte("derived-secret"), nil
		},
		deriveVaultKey: func([]byte, []byte, cryptoutil.KDFParams) ([]byte, error) {
			return testVaultKey(), nil
		},
		newClientID: func() string {
			return "client-1"
		},
		newItemID: func() string {
			return "item-1"
		},
		now: func() time.Time {
			return time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)
		},
	}

	return deps, store, api, &stdout, &stderr
}

func testProfile(t *testing.T) localstore.Profile {
	t.Helper()

	params := cryptoutil.KDFParams{
		Algorithm:   cryptoutil.KDFAlgorithmArgon2id,
		MemoryKiB:   8,
		Iterations:  1,
		Parallelism: 1,
		KeyLength:   cryptoutil.KeyLength32,
	}
	encodedParams, err := cryptoutil.MarshalKDFParams(params)
	if err != nil {
		t.Fatalf("MarshalKDFParams returned error: %v", err)
	}
	return localstore.Profile{
		ServerURL: "http://server.local",
		UserID:    "user-1",
		Login:     "alice",
		ClientID:  "client-1",
		AuthSalt:  []byte("auth-salt-123456"),
		VaultSalt: []byte("vault-salt-12345"),
		KDFParams: encodedParams,
	}
}

func testVaultKey() []byte {
	return bytes.Repeat([]byte{9}, cryptoutil.KeyLength32)
}

func testSession() clientapi.Session {
	params := cryptoutil.KDFParams{
		Algorithm:   cryptoutil.KDFAlgorithmArgon2id,
		MemoryKiB:   8,
		Iterations:  1,
		Parallelism: 1,
		KeyLength:   cryptoutil.KeyLength32,
	}
	now := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)
	return clientapi.Session{
		UserID:           "user-1",
		Login:            "alice",
		AccessToken:      "access-token",
		AccessExpiresAt:  now.Add(time.Minute),
		RefreshToken:     "refresh-token",
		RefreshExpiresAt: now.Add(time.Hour),
		AuthSalt:         base64.StdEncoding.EncodeToString([]byte("auth-salt")),
		VaultSalt:        base64.StdEncoding.EncodeToString([]byte("vault-salt")),
		KDFParams:        &params,
	}
}

func decodeBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return decoded
}

func testSyncItem(id string, revision int64) clientapi.SyncItem {
	return clientapi.SyncItem{
		ID:               id,
		ServerRevision:   revision,
		EncryptedPayload: base64.StdEncoding.EncodeToString([]byte(id + "-ciphertext")),
		PayloadNonce:     base64.StdEncoding.EncodeToString([]byte(id + "-nonce")),
		PayloadVersion:   1,
		UpdatedAt:        time.Date(2026, 7, 3, 10, int(revision), 0, 0, time.UTC),
	}
}

type fakePrompter struct {
	secret  []byte
	secrets [][]byte
	next    int
}

func (p *fakePrompter) ReadSecret(string) ([]byte, error) {
	if p.next < len(p.secrets) {
		value := p.secrets[p.next]
		p.next++
		return append([]byte(nil), value...), nil
	}
	return append([]byte(nil), p.secret...), nil
}

type fakeAPI struct {
	session         clientapi.Session
	registerRequest clientapi.CredentialsRequest
	loginRequest    clientapi.CredentialsRequest
	loginErr        error
	refreshToken    string
	refreshCount    int
	refreshErr      error
	logoutToken     string
	pushToken       string
	pushTokens      []string
	pushResponse    clientapi.PushResponse
	pushErrors      []error
	pushed          []clientapi.PushItem
	pullToken       string
	pullTokens      []string
	pullSince       int64
	pullSinceValues []int64
	changes         clientapi.Changes
	pullChanges     []clientapi.Changes
	pullErrors      []error
}

func (a *fakeAPI) Register(_ context.Context, request clientapi.CredentialsRequest) (clientapi.Session, error) {
	a.registerRequest = request
	return a.session, nil
}

func (a *fakeAPI) Login(_ context.Context, request clientapi.CredentialsRequest) (clientapi.Session, error) {
	a.loginRequest = request
	if a.loginErr != nil {
		return clientapi.Session{}, a.loginErr
	}
	return a.session, nil
}

func (a *fakeAPI) Refresh(_ context.Context, refreshToken string) (clientapi.Session, error) {
	a.refreshToken = refreshToken
	a.refreshCount++
	if a.refreshErr != nil {
		return clientapi.Session{}, a.refreshErr
	}
	return a.session, nil
}

func (a *fakeAPI) Logout(_ context.Context, refreshToken string) error {
	a.logoutToken = refreshToken
	return nil
}

func (a *fakeAPI) PushChanges(_ context.Context, accessToken string, items []clientapi.PushItem) (clientapi.PushResponse, error) {
	a.pushToken = accessToken
	a.pushTokens = append(a.pushTokens, accessToken)
	a.pushed = append([]clientapi.PushItem(nil), items...)
	if len(a.pushErrors) > 0 {
		err := a.pushErrors[0]
		a.pushErrors = a.pushErrors[1:]
		return clientapi.PushResponse{}, err
	}
	return a.pushResponse, nil
}

func (a *fakeAPI) PullChanges(_ context.Context, accessToken string, sinceRevision int64) (clientapi.Changes, error) {
	a.pullToken = accessToken
	a.pullTokens = append(a.pullTokens, accessToken)
	a.pullSince = sinceRevision
	a.pullSinceValues = append(a.pullSinceValues, sinceRevision)
	if len(a.pullErrors) > 0 {
		err := a.pullErrors[0]
		a.pullErrors = a.pullErrors[1:]
		return clientapi.Changes{}, err
	}
	if len(a.pullChanges) > 0 {
		changes := a.pullChanges[0]
		a.pullChanges = a.pullChanges[1:]
		return changes, nil
	}
	return a.changes, nil
}

type fakeStore struct {
	profile    localstore.Profile
	session    localstore.Session
	status     localstore.Status
	items      map[string]localstore.Item
	conflicts  map[string]localstore.Conflict
	hasProfile bool
	hasSession bool
}

func (s *fakeStore) SaveProfile(_ context.Context, profile localstore.Profile) error {
	s.profile = profile
	s.hasProfile = true
	return nil
}

func (s *fakeStore) Profile(context.Context) (localstore.Profile, error) {
	if !s.hasProfile {
		return localstore.Profile{}, localstore.ErrNotFound
	}
	return s.profile, nil
}

func (s *fakeStore) SaveSession(_ context.Context, session localstore.Session) error {
	s.session = session
	s.hasSession = true
	return nil
}

func (s *fakeStore) Session(context.Context) (localstore.Session, error) {
	if !s.hasSession {
		return localstore.Session{}, localstore.ErrNotFound
	}
	return s.session, nil
}

func (s *fakeStore) ClearSession(context.Context) error {
	s.hasSession = false
	return nil
}

func (s *fakeStore) Status(context.Context) (localstore.Status, error) {
	if s.status.HasProfile || s.status.HasSession {
		return s.status, nil
	}
	itemCount := 0
	dirtyCount := 0
	for _, item := range s.items {
		if item.DeletedAt == nil {
			itemCount++
		}
		if item.DirtyState != localstore.DirtyStateClean {
			dirtyCount++
		}
	}
	return localstore.Status{
		HasProfile:    s.hasProfile,
		HasSession:    s.hasSession,
		ServerURL:     s.profile.ServerURL,
		UserID:        s.profile.UserID,
		Login:         s.profile.Login,
		ClientID:      s.profile.ClientID,
		ItemCount:     itemCount,
		DirtyCount:    dirtyCount,
		ConflictCount: len(s.conflicts),
	}, nil
}

func (s *fakeStore) SaveItem(_ context.Context, item localstore.Item) error {
	if s.items == nil {
		s.items = map[string]localstore.Item{}
	}
	s.items[item.ID] = item.Clone()
	return nil
}

func (s *fakeStore) SaveItemAndClearConflict(ctx context.Context, item localstore.Item) error {
	if err := s.SaveItem(ctx, item); err != nil {
		return err
	}
	return s.ClearConflict(ctx, item.ID)
}

func (s *fakeStore) SaveItemAndConflict(ctx context.Context, item localstore.Item, conflict localstore.Conflict) error {
	if err := s.SaveItem(ctx, item); err != nil {
		return err
	}
	return s.SaveConflict(ctx, conflict)
}

func (s *fakeStore) Item(_ context.Context, id string) (localstore.Item, error) {
	item, ok := s.items[id]
	if !ok {
		return localstore.Item{}, localstore.ErrNotFound
	}
	return item.Clone(), nil
}

func (s *fakeStore) ListItems(_ context.Context, includeDeleted bool) ([]localstore.Item, error) {
	items := make([]localstore.Item, 0, len(s.items))
	for _, item := range s.items {
		if !includeDeleted && item.DeletedAt != nil {
			continue
		}
		items = append(items, item.Clone())
	}
	return items, nil
}

func (s *fakeStore) DeleteItem(_ context.Context, id string, deletedAt time.Time) error {
	item, ok := s.items[id]
	if !ok {
		return localstore.ErrNotFound
	}
	item.DeletedAt = &deletedAt
	item.DirtyState = localstore.DirtyStateDelete
	item.UpdatedAt = deletedAt
	s.items[id] = item.Clone()
	return nil
}

func (s *fakeStore) SaveConflict(_ context.Context, conflict localstore.Conflict) error {
	if s.conflicts == nil {
		s.conflicts = map[string]localstore.Conflict{}
	}
	s.conflicts[conflict.ItemID] = conflict.Clone()
	return nil
}

func (s *fakeStore) Conflict(_ context.Context, itemID string) (localstore.Conflict, error) {
	conflict, ok := s.conflicts[itemID]
	if !ok {
		return localstore.Conflict{}, localstore.ErrNotFound
	}
	return conflict.Clone(), nil
}

func (s *fakeStore) ListConflicts(context.Context) ([]localstore.Conflict, error) {
	conflicts := make([]localstore.Conflict, 0, len(s.conflicts))
	for _, conflict := range s.conflicts {
		conflicts = append(conflicts, conflict.Clone())
	}
	return conflicts, nil
}

func (s *fakeStore) ClearConflict(_ context.Context, itemID string) error {
	delete(s.conflicts, itemID)
	return nil
}

func (s *fakeStore) Close() error {
	return nil
}
