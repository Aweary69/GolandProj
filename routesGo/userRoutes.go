package routes

import (
	"github.com/gorilla/mux"
	"github.com/yourusername/GolandProj/controllers"
)

// RegisterRoutes sets up the user-related routesforGO
func RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/register", controllers.RegisterUser).Methods("POST")
	router.HandleFunc("/login", controllers.LoginUser).Methods("POST")
	router.HandleFunc("/user/{id}", controllers.GetUser).Methods("GET")
	router.HandleFunc("/user/profile", controllers.GetUserProfile).Methods("GET")
}
