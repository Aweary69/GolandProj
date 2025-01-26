package controllersGO

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"net/http"
)

// Mock User Model
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

var mockUsers = []User{
	{ID: 1, Username: "JohnDoe", Email: "john@example.com", Password: "password123"},
}

// RegisterUser handles user registration
func RegisterUser(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	user.ID = len(mockUsers) + 1
	mockUsers = append(mockUsers, user)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

// LoginUser handles user login
func LoginUser(w http.ResponseWriter, r *http.Request) {
	var credentials User
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	for _, user := range mockUsers {
		if user.Email == credentials.Email && user.Password == credentials.Password {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(user)
			return
		}
	}
	http.Error(w, "Invalid email or password", http.StatusUnauthorized)
}

// GetUser retrieves a specific user by ID
func GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	for _, user := range mockUsers {
		if string(user.ID) == id {
			json.NewEncoder(w).Encode(user)
			return
		}
	}
	http.NotFound(w, r)
}
