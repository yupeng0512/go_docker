package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLoadConfigFromEnvironment(t *testing.T) {
	original := append([]byte(nil), key...)
	t.Cleanup(func() { key = original })

	t.Run("missing", func(t *testing.T) {
		key = []byte("existing-key")
		t.Setenv("ENCRYPTION_KEY", "")
		if err := loadConfig(); err == nil {
			t.Fatal("expected a missing key error")
		}
		if !bytes.Equal(key, []byte("existing-key")) {
			t.Fatal("failed load must not replace the existing key")
		}
	})

	for _, invalid := range []string{
		"too-short",
		base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),
		base64.StdEncoding.EncodeToString([]byte("0123456789abcdefghijklmn")),
		"not-base64",
		base64.StdEncoding.EncodeToString([]byte("0123456789abcdefghijklmnopqrstuv")) + "\n",
	} {
		t.Run("invalid length", func(t *testing.T) {
			key = []byte("existing-key")
			t.Setenv("ENCRYPTION_KEY", invalid)
			if err := loadConfig(); err == nil {
				t.Fatal("expected an invalid key length error")
			}
			if !bytes.Equal(key, []byte("existing-key")) {
				t.Fatal("failed load must not replace the existing key")
			}
		})
	}

	validKey := []byte("0123456789abcdefghijklmnopqrstuv")
	valid := base64.StdEncoding.EncodeToString(validKey)
	t.Setenv("ENCRYPTION_KEY", valid)
	if err := loadConfig(); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if !bytes.Equal(key, validKey) {
		t.Fatal("loaded key does not match the environment")
	}
}

func TestAuthenticatedEnvelope(t *testing.T) {
	key := []byte("0123456789abcdefghijklmnopqrstuv")
	plaintext := []byte("personal recovery payload")

	first, err := encryptPayload(key, plaintext)
	if err != nil {
		t.Fatalf("encryptPayload() error = %v", err)
	}
	second, err := encryptPayload(key, plaintext)
	if err != nil {
		t.Fatalf("encryptPayload() second error = %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("ciphertexts must use independent random nonces")
	}
	if !bytes.HasPrefix(first, envelopeMagic) {
		t.Fatal("ciphertext does not carry the authenticated envelope version")
	}
	decrypted, err := decryptPayload(key, first)
	if err != nil {
		t.Fatalf("decryptPayload() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("round trip changed plaintext")
	}

	tampered := append([]byte(nil), first...)
	tampered[len(tampered)-1] ^= 1
	if _, err := decryptPayload(key, tampered); err == nil {
		t.Fatal("tampered ciphertext must fail closed")
	}
	wrongKey := []byte("abcdefghijklmnopqrstuvwxyzABCDEF")
	if _, err := decryptPayload(wrongKey, first); err == nil {
		t.Fatal("wrong key must fail closed")
	}
	if _, err := decryptPayload(key, []byte("legacy-cfb-without-version")); err == nil {
		t.Fatal("unversioned legacy ciphertext must fail closed")
	}
}

func TestMaximumPayloadRoundTrip(t *testing.T) {
	encryptionKey := []byte("0123456789abcdefghijklmnopqrstuv")
	plaintext := bytes.Repeat([]byte("x"), maxPayloadBytes)
	envelope, err := encryptPayload(encryptionKey, plaintext)
	if err != nil {
		t.Fatalf("encryptPayload() error = %v", err)
	}
	if len(envelope) > maxEnvelopeBytes {
		t.Fatalf("envelope size=%d exceeds limit=%d", len(envelope), maxEnvelopeBytes)
	}
	decrypted, err := decryptPayload(encryptionKey, envelope)
	if err != nil {
		t.Fatalf("decryptPayload() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("maximum payload round trip changed plaintext")
	}
}

func TestPostDecryptDoesNotWritePlaintext(t *testing.T) {
	originalDir := encryptedFileDir
	encryptedFileDir = t.TempDir()
	t.Cleanup(func() { encryptedFileDir = originalDir })
	key = []byte("0123456789abcdefghijklmnopqrstuv")
	ciphertext, err := encryptPayload(key, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("encryptedFile", "payload.gdk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(ciphertext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/post-decrypt", body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	context, _ := newTestContext(recorder, request)
	decryptFileHandlerByPost(context)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "hello" {
		t.Fatalf("unexpected response status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Content-Type") != "application/octet-stream" ||
		recorder.Header().Get("Cache-Control") != "no-store" ||
		recorder.Header().Get("X-Content-Type-Options") != "nosniff" ||
		!strings.HasPrefix(recorder.Header().Get("Content-Disposition"), "attachment;") {
		t.Fatalf("unsafe download headers: %#v", recorder.Header())
	}
	entries, err := os.ReadDir(encryptedFileDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("POST decrypt must not persist plaintext")
	}
}

func TestEncryptHandlerPersistsOnlyAuthenticatedCiphertext(t *testing.T) {
	originalDir := encryptedFileDir
	encryptedFileDir = filepath.Join(t.TempDir(), "ciphertext")
	if err := os.MkdirAll(encryptedFileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { encryptedFileDir = originalDir })
	key = []byte("0123456789abcdefghijklmnopqrstuv")
	plaintext := []byte("plaintext must not be persisted")

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "plain.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/encrypt", body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	context, _ := newTestContext(recorder, request)
	encryptFileHandler(context)
	if recorder.Code != http.StatusOK {
		t.Fatalf("encrypt status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	var response struct {
		EncryptedFile string `json:"encryptedFile"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !managedTokenRE.MatchString(response.EncryptedFile) {
		t.Fatalf("unsafe encrypted file token %q", response.EncryptedFile)
	}
	directoryInfo, err := os.Stat(encryptedFileDir)
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("ciphertext directory mode=%#o, want 0700", directoryInfo.Mode().Perm())
	}
	envelope, err := os.ReadFile(filepath.Join(encryptedFileDir, response.EncryptedFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(envelope, plaintext) {
		t.Fatal("persisted ciphertext contains plaintext")
	}
	decrypted, err := decryptPayload(key, envelope)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("persisted envelope is not recoverable: %v", err)
	}
}

func TestCiphertextDirectorySymlinkIsRejected(t *testing.T) {
	originalDir := encryptedFileDir
	outside := t.TempDir()
	encryptedFileDir = filepath.Join(t.TempDir(), "ciphertext-link")
	if err := os.Symlink(outside, encryptedFileDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { encryptedFileDir = originalDir })

	if _, err := persistCiphertext([]byte("ciphertext")); err == nil {
		t.Fatal("ciphertext directory symlink must be rejected")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("rejected directory symlink must not receive ciphertext")
	}
	token := strings.Repeat("0", managedTokenBytes*2) + ".gdk"
	if _, err := readManagedCiphertext(token); err == nil {
		t.Fatal("ciphertext directory symlink must be rejected on read")
	}
}

func TestGetDecryptRejectsPathEscape(t *testing.T) {
	originalDir := encryptedFileDir
	encryptedFileDir = t.TempDir()
	t.Cleanup(func() { encryptedFileDir = originalDir })
	outside := filepath.Join(t.TempDir(), "outside.gdk")
	if err := os.WriteFile(outside, []byte("not-secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, token := range []string{outside, "../outside.gdk", "not-a-managed-token"} {
		recorder := httptest.NewRecorder()
		request := newStoredDecryptRequest(token)
		context, _ := newTestContext(recorder, request)
		decryptStoredFileHandler(context)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("token %q status=%d, want %d", token, recorder.Code, http.StatusBadRequest)
		}
	}
}

func TestGetDecryptRejectsManagedSymlink(t *testing.T) {
	originalDir := encryptedFileDir
	encryptedFileDir = t.TempDir()
	t.Cleanup(func() { encryptedFileDir = originalDir })
	outside := filepath.Join(t.TempDir(), "outside.gdk")
	if err := os.WriteFile(outside, []byte("not-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("0", managedTokenBytes*2) + ".gdk"
	if err := os.Symlink(outside, filepath.Join(encryptedFileDir, token)); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := newStoredDecryptRequest(token)
	context, _ := newTestContext(recorder, request)
	decryptStoredFileHandler(context)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("symlink GET status=%d, want %d", recorder.Code, http.StatusInternalServerError)
	}
}

func TestManagedCiphertextPermissionsAndGetRoundTrip(t *testing.T) {
	originalDir := encryptedFileDir
	encryptedFileDir = t.TempDir()
	t.Cleanup(func() { encryptedFileDir = originalDir })
	key = []byte("0123456789abcdefghijklmnopqrstuv")
	plaintext := []byte("hello managed file")
	envelope, err := encryptPayload(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	token, err := persistCiphertext(envelope)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(encryptedFileDir, token))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("ciphertext mode=%#o, want 0600", info.Mode().Perm())
	}

	recorder := httptest.NewRecorder()
	request := newStoredDecryptRequest(token)
	context, _ := newTestContext(recorder, request)
	decryptStoredFileHandler(context)
	if recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), plaintext) {
		t.Fatalf("unexpected GET response status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Content-Type") != "application/octet-stream" ||
		recorder.Header().Get("Cache-Control") != "no-store" ||
		recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("unsafe GET headers: %#v", recorder.Header())
	}

	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 1
	if err := os.WriteFile(filepath.Join(encryptedFileDir, token), tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	request = newStoredDecryptRequest(token)
	context, _ = newTestContext(recorder, request)
	decryptStoredFileHandler(context)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("tampered GET status=%d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestRouterRemovesLegacyGetAndDefaultsToLoopback(t *testing.T) {
	if defaultListenAddr != "127.0.0.1:8888" {
		t.Fatalf("listen address %q is not loopback-only", defaultListenAddr)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/get-decrypt?encryptedFile=anything", nil)
	newRouter().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("legacy GET route status=%d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func newStoredDecryptRequest(token string) *http.Request {
	form := url.Values{"encryptedFile": {token}}
	request := httptest.NewRequest(http.MethodPost, "/stored-decrypt", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

func newTestContext(recorder *httptest.ResponseRecorder, request *http.Request) (*gin.Context, *gin.Engine) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	context := gin.CreateTestContextOnly(recorder, engine)
	context.Request = request
	return context, engine
}
