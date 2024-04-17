package main

import (
    "encoding/json"
    "net/http"
    "strings"
    "golang.org/x/crypto/bcrypt"
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

type User struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

var users = make(map[string]string)

func jwtMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tokenString := r.Header.Get("Authorization")
        if tokenString == "" {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            return []byte("lucaa1"), nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r)
    })
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Failed to hash password", http.StatusInternalServerError)
        return
    }

    users[user.Username] = string(hashedPassword)
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]string{"message": "You've signed up successfully"})
}


func signinHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    hashedPassword, ok := users[user.Username]
    if !ok {
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
    if err != nil {
        fmt.Println("Authentication failed:", err) // Add this line for logging
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    token := jwt.New(jwt.SigningMethodHS256)
    tokenString, err := token.SignedString([]byte("your_secret_key"))
    if err != nil {
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func main() {
    http.Handle("/", http.FileServer(http.Dir("./static")))
    http.HandleFunc("/signup", signupHandler)
    http.HandleFunc("/signin", signinHandler)

    http.ListenAndServe(":8080", nil)
}
