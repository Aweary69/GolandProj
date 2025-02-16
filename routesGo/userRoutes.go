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
		//userRoutes.POST("/", controllersGO.CreateUser)
		userRoutes.GET("/", controllersGO.GetAllUsers)
		userRoutes.GET("/:id", controllersGO.GetUserByID)
		//userRoutes.PUT("/:id", controllersGO.UpdateUserByID)
		userRoutes.DELETE("/:id", controllersGO.DeleteUserByID)
		userRoutes.GET("/get-profile", controllersGO.GetUserProfiles)
		userRoutes.GET("/user", middleware.AuthMiddleware(), controllersGO.GetUser)
		userRoutes.POST("/send-reset-code", controllersGO.SendResetCode)
		userRoutes.POST("/verify-reset-code", controllersGO.VerifyResetCode)
		userRoutes.POST("/reset-password", controllersGO.ResetPassword)
		userRoutes.POST("/change-password", middleware.AuthMiddleware(), controllersGO.ChangePassword)
		userRoutes.POST("/apply", middleware.AuthMiddleware(), controllersGO.HandleApplication)
		userRoutes.GET("/application-status", middleware.AuthMiddleware(), controllersGO.GetApplicationStatus)
		userRoutes.GET("/my-application", middleware.AuthMiddleware(), controllersGO.GetUserApplicationStatus)
		userRoutes.DELETE("/delete-application", middleware.AuthMiddleware(), controllersGO.DeleteApplication)

	}
	// Регистрация и логин
	router.POST("/register", controllersGO.RegisterUser)
	router.POST("/login", controllersGO.LoginUser)
}
