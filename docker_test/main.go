package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/gin-gonic/gin"
)

const (
	encryptionKeyBytes = 32
	maxPayloadBytes    = 32 << 20
	managedTokenBytes  = 16
	maxEnvelopeBytes   = maxPayloadBytes + 64
	maxMultipartBytes  = maxEnvelopeBytes + 64<<10
	maxTokenFormBytes  = 1024
	defaultListenAddr  = "127.0.0.1:8888"
)

var (
	envelopeMagic    = []byte("GDK1")
	managedTokenRE   = regexp.MustCompile(`^[0-9a-f]{32}\.gdk$`)
	encryptedFileDir = "./attachment/encrypt_file"
	key              []byte
)

// loadConfig loads an AES-256 key from canonical Base64 without changing the
// active key when validation fails.
func loadConfig() error {
	encoded := os.Getenv("ENCRYPTION_KEY")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != encryptionKeyBytes || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return fmt.Errorf(
			"ENCRYPTION_KEY must be standard Base64 encoding of exactly %d bytes",
			encryptionKeyBytes,
		)
	}
	key = append([]byte(nil), decoded...)
	return nil
}

// encryptPayload returns a versioned AES-GCM envelope. The magic bytes are
// authenticated as additional data so an attacker cannot downgrade formats.
func encryptPayload(encryptionKey, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(encryptionKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	envelope := make([]byte, 0, len(envelopeMagic)+len(nonce)+len(plaintext)+gcm.Overhead())
	envelope = append(envelope, envelopeMagic...)
	envelope = append(envelope, nonce...)
	envelope = gcm.Seal(envelope, nonce, plaintext, envelopeMagic)
	return envelope, nil
}

func decryptPayload(encryptionKey, envelope []byte) ([]byte, error) {
	gcm, err := newGCM(encryptionKey)
	if err != nil {
		return nil, err
	}
	headerSize := len(envelopeMagic) + gcm.NonceSize()
	if len(envelope) < headerSize+gcm.Overhead() || !bytes.Equal(envelope[:len(envelopeMagic)], envelopeMagic) {
		return nil, errors.New("unsupported or truncated encrypted envelope")
	}
	nonce := envelope[len(envelopeMagic):headerSize]
	ciphertext := envelope[headerSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, envelopeMagic)
	if err != nil {
		return nil, errors.New("encrypted envelope authentication failed")
	}
	return plaintext, nil
}

func newGCM(encryptionKey []byte) (cipher.AEAD, error) {
	if len(encryptionKey) != encryptionKeyBytes {
		return nil, fmt.Errorf("encryption key must contain exactly %d bytes", encryptionKeyBytes)
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("initialize AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize GCM: %w", err)
	}
	return gcm, nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("payload exceeds %d-byte limit", limit)
	}
	return payload, nil
}

func randomManagedToken() (string, error) {
	raw := make([]byte, managedTokenBytes)
	if _, err := io.ReadFull(cryptorand.Reader, raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw) + ".gdk", nil
}

func persistCiphertext(envelope []byte) (string, error) {
	if err := ensurePrivateCiphertextDirectory(); err != nil {
		return "", err
	}
	for attempts := 0; attempts < 3; attempts++ {
		token, err := randomManagedToken()
		if err != nil {
			return "", err
		}
		path := filepath.Join(encryptedFileDir, token)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		committed := false
		defer func() {
			_ = file.Close()
			if !committed {
				_ = os.Remove(path)
			}
		}()
		if _, err := file.Write(envelope); err != nil {
			return "", err
		}
		if err := file.Sync(); err != nil {
			return "", err
		}
		if err := file.Close(); err != nil {
			return "", err
		}
		committed = true
		return token, nil
	}
	return "", errors.New("could not allocate a unique encrypted file token")
}

func ensurePrivateCiphertextDirectory() error {
	info, err := os.Lstat(encryptedFileDir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(encryptedFileDir, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(encryptedFileDir)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("encrypted file directory must be a real directory")
	}
	return os.Chmod(encryptedFileDir, 0o700)
}

func verifyCiphertextDirectory() error {
	info, err := os.Lstat(encryptedFileDir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("encrypted file directory must be a real directory")
	}
	return nil
}

func readManagedCiphertext(token string) ([]byte, error) {
	if !managedTokenRE.MatchString(token) {
		return nil, errors.New("invalid encrypted file token")
	}
	if err := verifyCiphertextDirectory(); err != nil {
		return nil, err
	}
	path := filepath.Join(encryptedFileDir, token)
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > maxEnvelopeBytes {
		return nil, errors.New("encrypted file is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("encrypted file changed during open")
	}
	return readBounded(file, maxEnvelopeBytes)
}

func readMultipartFile(request *http.Request, fieldName string, limit int64) ([]byte, error) {
	reader, err := request.MultipartReader()
	if err != nil {
		return nil, err
	}
	var payload []byte
	found := false
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if part.FormName() != fieldName || part.FileName() == "" {
			_ = part.Close()
			continue
		}
		if found {
			_ = part.Close()
			return nil, errors.New("duplicate uploaded file")
		}
		payload, err = readBounded(part, limit)
		_ = part.Close()
		if err != nil {
			return nil, err
		}
		found = true
	}
	if !found {
		return nil, errors.New("missing uploaded file")
	}
	return payload, nil
}

func encryptFileHandler(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxMultipartBytes)
	plaintext, err := readMultipartFile(c.Request, "file", maxPayloadBytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file payload"})
		return
	}
	envelope, err := encryptPayload(key, plaintext)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "encryption failed"})
		return
	}
	token, err := persistCiphertext(envelope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "encrypted file storage failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"encryptedFile": token})
}

func decryptFileHandlerByPost(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxMultipartBytes)
	envelope, err := readMultipartFile(c.Request, "encryptedFile", maxEnvelopeBytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid encrypted payload"})
		return
	}
	plaintext, err := decryptPayload(key, envelope)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "encrypted payload rejected"})
		return
	}
	writeDownload(c, plaintext)
}

func decryptStoredFileHandler(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxTokenFormBytes)
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid encrypted file request"})
		return
	}
	tokens := c.Request.PostForm["encryptedFile"]
	if len(tokens) != 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "exactly one encrypted file token is required"})
		return
	}
	token := tokens[0]
	if !managedTokenRE.MatchString(token) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid encrypted file token"})
		return
	}
	envelope, err := readManagedCiphertext(token)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusNotFound, gin.H{"error": "encrypted file not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "encrypted file read failed"})
		return
	}
	plaintext, err := decryptPayload(key, envelope)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "encrypted payload rejected"})
		return
	}
	writeDownload(c, plaintext)
}

func writeDownload(c *gin.Context, plaintext []byte) {
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Disposition", `attachment; filename="decrypted.bin"`)
	c.Header("Pragma", "no-cache")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Data(http.StatusOK, "application/octet-stream", plaintext)
}

func newRouter() *gin.Engine {
	router := gin.Default()
	router.POST("/encrypt", encryptFileHandler)
	router.POST("/post-decrypt", decryptFileHandlerByPost)
	router.POST("/stored-decrypt", decryptStoredFileHandler)
	return router
}

func main() {
	if err := loadConfig(); err != nil {
		panic(err)
	}
	if err := newRouter().Run(defaultListenAddr); err != nil {
		panic(err)
	}
}
