package routesGo

import (
	"CarStore/controllersGO"
	"github.com/gin-gonic/gin"
)

// RegisterCarRoutes sets up all car-related routes
func RegisterCarRoutes(router *gin.Engine) {
	carRoutes := router.Group("/api/cars")
	{
		carRoutes.GET("/", controllersGO.GetAllCars)
		carRoutes.GET("/:id", controllersGO.GetCarByID)
		carRoutes.POST("/", controllersGO.CreateCar)
		carRoutes.PUT("/:id", controllersGO.UpdateCar)
		carRoutes.DELETE("/:id", controllersGO.DeleteCar)

		// Filtering route
		carRoutes.GET("/filter", controllersGO.FilterCars)
	}
}
