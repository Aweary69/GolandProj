package routesGo

import (
	"CarStore/controllersGO"
	"github.com/gorilla/mux"
)

// RegisterRoutes sets up the user-related routes
func RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/register", controllersGO.RegisterUser).Methods("POST")
	router.HandleFunc("/login", controllersGO.LoginUser).Methods("POST")
	router.HandleFunc("/user/{id}", controllersGO.GetUser).Methods("GET")
}
