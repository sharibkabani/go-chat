package api

import (
    "database/sql"
    "encoding/json"
    "net/http"
    "time"
    "os"
    "github.com/gorilla/mux"
    "golang.org/x/crypto/bcrypt"
    "github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte(os.Getenv("JWT_SECRET"))

type Claims struct {
    Username string `json:"username"`
    jwt.StandardClaims
}

// Handler struct to hold the database connection
type Handler struct {
    DB *sql.DB
}

// NewHandler creates a new Handler
func NewHandler(db *sql.DB) *Handler {
    return &Handler{DB: db}
}

func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

// CreateUser handles the POST /users endpoint
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
    var user struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    var userID int
    user.Password, _ = HashPassword(user.Password)
    err := h.DB.QueryRow("INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id", user.Username, user.Password).Scan(&userID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    response := struct {
        ID       int    `json:"id"`
        Username string `json:"username"`
    }{
        ID:       userID,
        Username: user.Username,
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(response)
}

// DeleteUser handles the DELETE /users/{id} endpoint
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id := vars["id"]

    _, err := h.DB.Exec("DELETE FROM users WHERE id = $1", id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

// UpdateUser handles the PUT /users/{id} endpoint
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id := vars["id"]

    var user struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    user.Password, _ = HashPassword(user.Password)
    _, err := h.DB.Exec("UPDATE users SET username = $1, password = $2 WHERE id = $3", user.Username, user.Password, id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
}

// GetUser handles the GET /users/{id} endpoint
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id := vars["id"]

    var user struct {
        ID       int    `json:"id"`
        Username string `json:"username"`
    }
    err := h.DB.QueryRow("SELECT id, username FROM users WHERE id = $1", id).Scan(&user.ID, &user.Username)
    if err != nil {
        if err == sql.ErrNoRows {
            http.Error(w, "User not found", http.StatusNotFound)
        } else {
            http.Error(w, err.Error(), http.StatusInternalServerError)
        }
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(user)
}

// Login handles the POST /login endpoint
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
    var creds struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    var storedHash string
    err := h.DB.QueryRow("SELECT password FROM users WHERE username = $1", creds.Username).Scan(&storedHash)
    if err != nil {
        if err == sql.ErrNoRows {
            http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        } else {
            http.Error(w, err.Error(), http.StatusInternalServerError)
        }
        return
    }

    if !CheckPasswordHash(creds.Password, storedHash) {
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        Username: creds.Username,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    http.SetCookie(w, &http.Cookie{
        Name:    "token",
        Value:   tokenString,
        Expires: expirationTime,
    })
}

// Middleware to protect routes
func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie("token")
        if err != nil {
            if err == http.ErrNoCookie {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        tokenStr := cookie.Value
        claims := &Claims{}

        token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
            return jwtKey, nil
        })
        if err != nil {
            if err == jwt.ErrSignatureInvalid {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        if !token.Valid {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r)
    })
}