package controllersGO

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"CarStore/models"
	"github.com/gin-gonic/gin"
)

var userCollection *mongo.Collection

func SetUserCollection(collection *mongo.Collection) {
	userCollection = collection
}

func hashPassword(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

func RegisterUser(c *gin.Context) {
	var user models.User

	fmt.Println("Raw request body:", c.Request.Body) // Логируем входящие данные

	if err := c.ShouldBindJSON(&user); err != nil {
		fmt.Println("Ошибка парсинга JSON:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input", "details": err.Error()})
		return
	}

	fmt.Println("Получены данные пользователя:", user)

	var existingUser models.User
	err := userCollection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&existingUser)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already registered"})
		return
	}

	user.Password = hashPassword(user.Password)
	user.ID = primitive.NewObjectID()
	user.CreatedAt = time.Now()

	_, err = userCollection.InsertOne(context.TODO(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not register user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

// Read secret key from .env
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

// GenerateJWT creates a JWT token for authentication
func GenerateJWT(userID string) (string, error) {
	claims := jwt.MapClaims{
		"userID": userID,
		"exp":    time.Now().Add(time.Hour * 12).Unix(), // Expires in 12 hours
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 🔹 Generate the signed JWT
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	fmt.Println("Generated Token:", signedToken) // ✅ Debugging

	return signedToken, nil
}

func LoginUser(c *gin.Context) {
	var loginData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var user models.User
	err := userCollection.FindOne(context.TODO(), bson.M{"email": loginData.Email}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	if user.Password != hashPassword(loginData.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token, err := GenerateJWT(user.ID.Hex())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	fmt.Println("Generated Token for user:", token) // ✅ Debugging

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   token,
	})
}

func CreateUser(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Check if email already exists
	var existingUser models.User
	err := userCollection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&existingUser)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already registered"})
		return
	}

	// Hash password and create user
	user.Password = hashPassword(user.Password)
	user.ID = primitive.NewObjectID()
	user.CreatedAt = time.Now()

	_, err = userCollection.InsertOne(context.TODO(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not register user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

// 🔹 Get All Users
func GetAllUsers(c *gin.Context) {
	cursor, err := userCollection.Find(context.TODO(), bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	defer cursor.Close(context.TODO())

	var users []models.User
	for cursor.Next(context.TODO()) {
		var user models.User
		if err := cursor.Decode(&user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error decoding user data"})
			return
		}
		user.Password = "" // Hide password
		users = append(users, user)
	}

	c.JSON(http.StatusOK, users)
}

// 🔹 Get a Single User by ID
func GetUserByID(c *gin.Context) {
	id := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var user models.User
	err = userCollection.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	user.Password = "" // Hide password
	c.JSON(http.StatusOK, user)
}

// 🔹 Update User by ID
func UpdateUserByID(c *gin.Context) {
	id := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var updatedData models.User
	if err := c.ShouldBindJSON(&updatedData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Hash new password if provided
	if updatedData.Password != "" {
		updatedData.Password = hashPassword(updatedData.Password)
	}

	update := bson.M{
		"$set": bson.M{
			"name":       updatedData.Name,
			"email":      updatedData.Email,
			"password":   updatedData.Password,
			"created_at": time.Now(),
		},
	}

	result, err := userCollection.UpdateOne(context.TODO(), bson.M{"_id": objID}, update)
	if err != nil || result.ModifiedCount == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

// 🔹 Delete User by ID
func DeleteUserByID(c *gin.Context) {
	id := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	result, err := userCollection.DeleteOne(context.TODO(), bson.M{"_id": objID})
	if err != nil || result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func GetUserProfiles(c *gin.Context) {
	// Mock user ID (you should extract this from session/JWT later)
	userID := "65a1bc2d3e4f567890abcdef" // Replace with actual user session ID

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var user models.User
	err = userCollection.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Return only necessary user data
	c.JSON(http.StatusOK, gin.H{
		"id":    user.ID.Hex(),
		"name":  user.Name,
		"email": user.Email,
	})
}

func GetUser(c *gin.Context) {
	// Extract user ID from authentication (assuming middleware sets it in context)
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	objID, err := primitive.ObjectIDFromHex(userID.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var user models.User
	err = userCollection.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	// Return user data (excluding password)
	c.JSON(http.StatusOK, gin.H{
		"id":    user.ID.Hex(),
		"name":  user.Name,
		"email": user.Email,
	})
}
