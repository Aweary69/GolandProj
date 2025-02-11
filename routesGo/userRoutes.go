package routesGo

import (
	"CarStore/controllersGO" // Контроллеры
	"CarStore/middleware"
	"github.com/gin-gonic/gin"
)

// RegisterRoutes регистрирует роуты пользователя
func RegisterRoutes(router *gin.Engine) {
	userRoutes := router.Group("/api/users")
	{
		userRoutes.POST("/", controllersGO.CreateUser)
		userRoutes.GET("/", controllersGO.GetAllUsers)
		userRoutes.GET("/:id", controllersGO.GetUserByID)
		userRoutes.PUT("/:id", controllersGO.UpdateUserByID)
		userRoutes.DELETE("/:id", controllersGO.DeleteUserByID)
		userRoutes.GET("/get-profile", controllersGO.GetUserProfiles)
		userRoutes.GET("/user", middleware.AuthMiddleware(), controllersGO.GetUser)

	}
	// Регистрация и логин
	router.POST("/register", controllersGO.RegisterUser)
	router.POST("/login", controllersGO.LoginUser)
}
