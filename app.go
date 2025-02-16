package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"CarStore/controllersGO"
	"CarStore/routesGo"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
	fmt.Println("✅ Environment variables loaded")
}

// Подключение к MongoDB
func connectToMongoDB() *mongo.Client {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Ошибка загрузки .env файла: %v", err)
	}

	uri := os.Getenv("MONGO_URI")
	if uri == "" {
		log.Fatal("MONGO_URI не задан в .env")
	}

	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatalf("Ошибка подключения к MongoDB: %v", err)
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatalf("Ошибка пинга MongoDB: %v", err)
	}

	fmt.Println("Успешное подключение к MongoDB!")
	return client
}

func main() {
	loadEnv()                   // Load environment variables
	client = connectToMongoDB() // Подключаемся к базе данных

	// Устанавливаем коллекцию пользователей
	controllersGO.SetUserCollection(client.Database("carstore").Collection("users"))
	controllersGO.SetApplicationCollection(client.Database("carstore").Collection("applications"))

	// Создаем сервер
	router := gin.Default()

	// CORS Middleware (для разрешения запросов с фронтенда)
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	// Регистрируем маршруты из `userRoutes.go`
	routesGo.RegisterRoutes(router)

	// Раздача статических файлов
	router.Static("/static", "./static") // Serve files from /static

	// Загружаем страницу регистрации по умолчанию
	router.GET("/", func(c *gin.Context) {
		c.File("./static/home.html")
	})

	// Запускаем сервер
	port := "8000"
	fmt.Printf("Сервер запущен на порту %s...\n", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
}
