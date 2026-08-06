package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"vuln-scanner/internal/remotescan"
	"vuln-scanner/internal/store"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/ssh"
)

const maxRemoteTargets = 100

func (s *RESTServer) listRemoteCredentials(w http.ResponseWriter, r *http.Request) {
	tid, err := s.tid(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	creds, err := s.store.ListRemoteCredentials(r.Context(), tid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]interface{}, 0, len(creds))
	for i := range creds {
		out = append(out, remoteCredentialView(&creds[i]))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"credentials": out})
}

func (s *RESTServer) createRemoteCredential(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name       string `json:"name"`
		Username   string `json:"username"`
		AuthType   string `json:"auth_type"`
		Password   string `json:"password"`
		PrivateKey string `json:"private_key"`
		Passphrase string `json:"passphrase"`
		TenantID   int64  `json:"tenant_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	name := strings.TrimSpace(in.Name)
	username := strings.TrimSpace(in.Username)
	authType := strings.ToLower(strings.TrimSpace(in.AuthType))
	if name == "" || username == "" {
		writeError(w, http.StatusBadRequest, "name and username are required")
		return
	}
	if authType != remotescan.AuthTypePassword && authType != remotescan.AuthTypeKey {
		writeError(w, http.StatusBadRequest, "auth_type must be password or key")
		return
	}
	if s.remoteCipher == nil {
		writeError(w, http.StatusServiceUnavailable, "remote scan is disabled or the master key is not configured")
		return
	}

	var publicKeyOnce string
	pwdCipher, keyCipher, passCipher, err := encryptCredentialSecrets(s.remoteCipher, authType, in.Password, in.PrivateKey, in.Passphrase, &publicKeyOnce)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tenantID, err := s.effectiveTenant(r, in.TenantID)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	cred, err := s.store.CreateRemoteCredential(r.Context(), tenantID, name, username, authType, pwdCipher, keyCipher, passCipher, actorFromRequest(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]interface{}{"credential": remoteCredentialView(cred)}
	if publicKeyOnce != "" {
		resp["public_key"] = publicKeyOnce
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *RESTServer) updateRemoteCredential(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "credentialId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid credential id")
		return
	}
	var in struct {
		Name       string `json:"name"`
		Username   string `json:"username"`
		AuthType   string `json:"auth_type"`
		Password   string `json:"password"`
		PrivateKey string `json:"private_key"`
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if s.remoteCipher == nil {
		writeError(w, http.StatusServiceUnavailable, "remote scan is disabled or the master key is not configured")
		return
	}
	existing, err := s.requireRemoteCredential(r, id)
	if errors.Is(err, store.ErrRemoteCredentialNotFound) {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}
	if err != nil {
		writeScopeError(w, err)
		return
	}

	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = existing.Name
	}
	username := strings.TrimSpace(in.Username)
	if username == "" {
		username = existing.Username
	}
	authType := strings.ToLower(strings.TrimSpace(in.AuthType))
	if authType == "" {
		authType = existing.AuthType
	}
	if authType != remotescan.AuthTypePassword && authType != remotescan.AuthTypeKey {
		writeError(w, http.StatusBadRequest, "auth_type must be password or key")
		return
	}

	curPwd, err := s.remoteCipher.Decrypt(existing.PasswordCiphertext)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential corrupted: "+err.Error())
		return
	}
	curKey, err := s.remoteCipher.Decrypt(existing.PrivateKeyCiphertext)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential corrupted: "+err.Error())
		return
	}
	curPass, err := s.remoteCipher.Decrypt(existing.PassphraseCiphertext)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential corrupted: "+err.Error())
		return
	}
	password := string(curPwd)
	privateKey := string(curKey)
	passphrase := string(curPass)
	if in.Password != "" {
		password = in.Password
	}
	if in.PrivateKey != "" {
		privateKey = in.PrivateKey
	}
	if in.Passphrase != "" {
		passphrase = in.Passphrase
	}

	var unused string
	pwdCipher, keyCipher, passCipher, err := encryptCredentialSecrets(s.remoteCipher, authType, password, privateKey, passphrase, &unused)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpdateRemoteCredential(r.Context(), id, name, username, pwdCipher, keyCipher, passCipher); err != nil {
		if errors.Is(err, store.ErrRemoteCredentialNotFound) {
			writeError(w, http.StatusNotFound, "credential not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	updated, err := s.store.GetRemoteCredential(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"credential": remoteCredentialView(updated)})
}

func (s *RESTServer) deleteRemoteCredential(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "credentialId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid credential id")
		return
	}
	if _, err := s.requireRemoteCredential(r, id); err != nil {
		if errors.Is(err, store.ErrRemoteCredentialNotFound) {
			writeError(w, http.StatusNotFound, "credential not found")
			return
		}
		writeScopeError(w, err)
		return
	}
	if err := s.store.RevokeRemoteCredential(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (s *RESTServer) createRemoteScan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CredentialID int64    `json:"credential_id"`
		Targets      []string `json:"targets"`
		Port         int      `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if in.CredentialID <= 0 {
		writeError(w, http.StatusBadRequest, "credential_id is required")
		return
	}
	if len(in.Targets) == 0 {
		writeError(w, http.StatusBadRequest, "targets is required")
		return
	}
	if len(in.Targets) > maxRemoteTargets {
		writeError(w, http.StatusBadRequest, "at most 100 targets per scan")
		return
	}
	port := in.Port
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		writeError(w, http.StatusBadRequest, "port must be in 1-65535")
		return
	}
	addresses := make([]string, 0, len(in.Targets))
	for _, raw := range in.Targets {
		addr, err := normalizeRemoteTarget(raw, port)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid target "+strconv.Quote(raw)+": "+err.Error())
			return
		}
		addresses = append(addresses, addr)
	}
	if _, err := s.requireRemoteCredential(r, in.CredentialID); err != nil {
		if errors.Is(err, store.ErrRemoteCredentialNotFound) {
			writeError(w, http.StatusNotFound, "credential not found")
			return
		}
		writeScopeError(w, err)
		return
	}
	tasks, err := s.store.CreateRemoteScanTasks(r.Context(), in.CredentialID, addresses, actorFromRequest(r))
	if errors.Is(err, store.ErrRemoteCredentialNotFound) {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}
	if errors.Is(err, store.ErrRemoteCredentialRevoked) {
		writeError(w, http.StatusBadRequest, "credential is revoked")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.worker != nil {
		s.worker.TriggerRemoteScan()
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"count": len(tasks),
		"tasks": tasks,
	})
}

func (s *RESTServer) listRemoteScanTasks(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	tid, err := s.tid(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	tasks, total, err := s.store.ListRemoteScanTasks(r.Context(), status, limit, offset, tid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"total": total, "tasks": tasks})
}

func (s *RESTServer) listRemoteHosts(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	tid, err := s.tid(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hosts, total, err := s.store.ListRemoteHosts(r.Context(), limit, offset, tid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"total": total, "hosts": hosts})
}

// encryptCredentialSecrets validates authType-specific input and returns the
// ciphertexts. For key auth with an omitted private key, a new ed25519
// keypair is generated and public_key_once is set.
func encryptCredentialSecrets(cp *remotescan.Cipher, authType, password, privateKey, passphrase string, publicKeyOnce *string) (string, string, string, error) {
	switch authType {
	case remotescan.AuthTypePassword:
		if password == "" {
			return "", "", "", errors.New("password is required for password auth")
		}
		pwd, err := cp.Encrypt([]byte(password))
		if err != nil {
			return "", "", "", err
		}
		return pwd, "", "", nil
	case remotescan.AuthTypeKey:
		keyPEM := strings.TrimSpace(privateKey)
		if keyPEM == "" {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return "", "", "", err
			}
			block, err := ssh.MarshalPrivateKey(priv, "vuln-scanner")
			if err != nil {
				return "", "", "", err
			}
			if passphrase != "" {
				block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "vuln-scanner", []byte(passphrase))
				if err != nil {
					return "", "", "", err
				}
			}
			keyPEM = string(pem.EncodeToMemory(block))
			sshPub, err := ssh.NewPublicKey(pub)
			if err != nil {
				return "", "", "", err
			}
			*publicKeyOnce = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
		}
		if _, err := parseRemotePrivateKey(keyPEM, passphrase); err != nil {
			return "", "", "", errors.New("invalid private key: " + err.Error())
		}
		keyCipher, err := cp.Encrypt([]byte(keyPEM))
		if err != nil {
			return "", "", "", err
		}
		passCipher, err := cp.Encrypt([]byte(passphrase))
		if err != nil {
			return "", "", "", err
		}
		return "", keyCipher, passCipher, nil
	default:
		return "", "", "", errors.New("auth_type must be password or key")
	}
}

func parseRemotePrivateKey(keyPEM, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(keyPEM), []byte(passphrase))
	}
	return ssh.ParsePrivateKey([]byte(keyPEM))
}

func normalizeRemoteTarget(raw string, defaultPort int) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t/\\\"") {
		return "", errors.New("invalid host")
	}
	if strings.Contains(raw, ":") {
		host, portStr, err := net.SplitHostPort(raw)
		if err != nil {
			return "", err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return "", errors.New("invalid port")
		}
		return net.JoinHostPort(host, portStr), nil
	}
	return net.JoinHostPort(raw, strconv.Itoa(defaultPort)), nil
}

func remoteCredentialView(c *store.RemoteCredential) map[string]interface{} {
	return map[string]interface{}{
		"id":         c.ID,
		"tenant_id":  c.TenantID,
		"name":       c.Name,
		"username":   c.Username,
		"auth_type":  c.AuthType,
		"created_by": c.CreatedBy,
		"created_at": c.CreatedAt,
		"updated_at": c.UpdatedAt,
		"revoked_at": c.RevokedAt,
	}
}

// requireRemoteCredential loads one credential and rejects access when the
// caller's tenant scope does not include the credential's tenant.
func (s *RESTServer) requireRemoteCredential(r *http.Request, id int64) (*store.RemoteCredential, error) {
	cred, err := s.store.GetRemoteCredential(r.Context(), id)
	if err != nil {
		return cred, err
	}
	tenantID, restrict, err := s.scope(r)
	if err != nil {
		return cred, err
	}
	if restrict && cred.TenantID != tenantID {
		return cred, errTenantForbidden
	}
	return cred, nil
}
