package controllersGO

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"net/http"
	"os"
	"strings"
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

// Reference to applications collection
var applicationCollection *mongo.Collection

func SetApplicationCollection(collection *mongo.Collection) {
	applicationCollection = collection
}

// ✅ Hash password securely using bcrypt
func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// ✅ Compare a password with its hashed version
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func RegisterUser(c *gin.Context) {
	var user models.User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input", "details": err.Error()})
		return
	}

	// Check if email is already registered
	var existingUser models.User
	err := userCollection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&existingUser)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already registered"})
		return
	}

	// ✅ Hash the password using bcrypt
	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}
	user.Password = hashedPassword

	// Save user to database
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

	// Find user by email
	var user models.User
	err := userCollection.FindOne(context.TODO(), bson.M{"email": loginData.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// ✅ Check if the entered password matches the hashed password
	if !checkPasswordHash(loginData.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token
	token, err := GenerateJWT(user.ID.Hex())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   token,
	})
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

func generateResetCode() string {
	return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000) // Generates a 6-digit code
}

// Controller to handle sending reset code (prints to terminal instead of sending email)
func SendResetCode(c *gin.Context) {
	var request struct {
		Email string `json:"email"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Check if user exists
	var user models.User
	err := userCollection.FindOne(context.TODO(), bson.M{"email": request.Email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	// Generate and store the reset code
	resetCode := generateResetCode()
	_, err = userCollection.UpdateOne(
		context.TODO(),
		bson.M{"email": request.Email},
		bson.M{"$set": bson.M{"resetCode": resetCode, "resetExpires": time.Now().Add(10 * time.Minute)}}, // Expires in 10 minutes
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not store reset code"})
		return
	}

	// Print the reset code instead of sending an email
	fmt.Printf("Reset code for %s: %s\n", request.Email, resetCode) // ✅ Prints to the terminal

	c.JSON(http.StatusOK, gin.H{"message": "Reset code generated. Check server logs for the code."})
}

// Controller to verify reset code
func VerifyResetCode(c *gin.Context) {
	var request struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Find user by email
	var user struct {
		ResetCode    string    `bson:"resetCode"`
		ResetExpires time.Time `bson:"resetExpires"`
	}
	err := userCollection.FindOne(context.TODO(), bson.M{"email": request.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found or no reset code generated"})
		return
	}

	// Check if the code matches and hasn't expired
	if user.ResetCode != request.Code {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid reset code"})
		return
	}

	if time.Now().After(user.ResetExpires) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Reset code expired"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Reset code verified. You may reset your password."})
}

// Controller to reset the password
func ResetPassword(c *gin.Context) {
	var request struct {
		Email       string `json:"email"`
		NewPassword string `json:"newPassword"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Find user by email
	var user models.User
	err := userCollection.FindOne(context.TODO(), bson.M{"email": request.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found or reset code missing"})
		return
	}

	// ✅ Hash the new password using bcrypt
	hashedPassword, err := hashPassword(request.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Update the user's password and remove reset code
	_, err = userCollection.UpdateOne(
		context.TODO(),
		bson.M{"email": request.Email},
		bson.M{"$set": bson.M{"password": hashedPassword}, "$unset": bson.M{"resetCode": "", "resetExpires": ""}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

func ChangePassword(c *gin.Context) {
	var request struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// ✅ Debug: Check if authentication middleware is working
	userID, exists := c.Get("userID")
	if !exists {
		fmt.Println("🚨 ERROR: No userID found in context") // Debugging
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	fmt.Println("🔹 Extracted userID from token:", userID) // ✅ Debugging

	objID, err := primitive.ObjectIDFromHex(userID.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// ✅ Find the user
	var user models.User
	err = userCollection.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// ✅ Check if old password matches
	if !checkPasswordHash(request.OldPassword, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Old password is incorrect"})
		return
	}

	// ✅ Hash the new password
	hashedPassword, err := hashPassword(request.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// ✅ Update password
	_, err = userCollection.UpdateOne(
		context.TODO(),
		bson.M{"_id": objID},
		bson.M{"$set": bson.M{"password": hashedPassword}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update password"})
		return
	}

	fmt.Println("✅ Password changed successfully for user:", userID) // Debugging
	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// HandleApplication processes car purchase applications
func HandleApplication(c *gin.Context) {
	userID, exists := c.Get("userID") // ✅ Get authenticated user's ID
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var app models.Application

	// Parse request JSON
	if err := c.ShouldBindJSON(&app); err != nil {
		fmt.Println("JSON Binding Error:", err)
		c.JSON(400, gin.H{"error": "Invalid request data", "details": err.Error()})
		return
	}

	// Set application metadata
	app.ID = primitive.NewObjectID()
	app.UserID, _ = primitive.ObjectIDFromHex(userID.(string)) // ✅ Assign user ID
	app.CreatedAt = time.Now()
	app.Status = "Pending"
	app.Meeting = nil

	// Insert into database
	_, err := applicationCollection.InsertOne(context.TODO(), app)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to submit application"})
		return
	}

	// Log application in terminal
	fmt.Printf("\n📩 Application received from %s\n", app.FullName)
	fmt.Println("⚡ Will you accept or decline? (Type 'Accept' or 'Decline'): ")

	// Read admin response from terminal
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(response) // ✅ Trim spaces and newlines
	response = strings.ToLower(response)   // ✅ Convert to lowercase for consistency

	if response == "accept" {
		// Generate random meeting date within the next 3 months (between 11:00 - 20:00)
		randomDays := rand.Intn(90) // Within 3 months
		meetingDate := time.Now().AddDate(0, 0, randomDays)

		// Set random time between 11:00 - 20:00
		randomHour := 11 + rand.Intn(10)
		meetingDate = time.Date(meetingDate.Year(), meetingDate.Month(), meetingDate.Day(), randomHour, 0, 0, 0, meetingDate.Location())

		// Update application with meeting date
		_, err := applicationCollection.UpdateOne(
			context.TODO(),
			bson.M{"_id": app.ID},
			bson.M{"$set": bson.M{"status": "Accepted", "meeting": meetingDate}},
		)
		if err != nil {
			fmt.Println("❌ Error updating application with meeting date:", err)
			c.JSON(500, gin.H{"error": "Failed to schedule meeting"})
			return
		}

		fmt.Printf("✅ Application Accepted! 📅 Meeting scheduled on %s\n", meetingDate.Format("2006-01-02 15:04"))

	} else {
		// Update application status as declined
		_, err := applicationCollection.UpdateOne(
			context.TODO(),
			bson.M{"_id": app.ID},
			bson.M{"$set": bson.M{"status": "Declined"}},
		)
		if err != nil {
			fmt.Println("❌ Error updating application status:", err)
			c.JSON(500, gin.H{"error": "Failed to decline application"})
			return
		}

		fmt.Println("❌ Application Declined")
	}

	// Send response
	c.JSON(200, gin.H{"message": "Application processed successfully"})
}

func GetApplicationStatus(c *gin.Context) {
	// ✅ Get user ID from authentication middleware
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// ✅ Convert userID to ObjectID
	objID, err := primitive.ObjectIDFromHex(userID.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// 🔹 Debugging: Print userID being searched
	fmt.Println("🔎 Searching for application with userID:", objID.Hex())

	// ✅ Fix: Use a **string comparison** if the field is stored as a string
	filter := bson.M{"user_id": userID.(string)} // Try searching with string userID

	// ✅ Search for the application
	var app models.Application
	err = applicationCollection.FindOne(context.TODO(), filter).Decode(&app)

	// 🔹 If the first search fails, try using ObjectID format
	if err != nil {
		filter = bson.M{"user_id": objID} // Try searching with ObjectID format
		err = applicationCollection.FindOne(context.TODO(), filter).Decode(&app)
	}

	// ✅ Handle case where no application is found
	if err != nil {
		fmt.Println("❌ No application found for user:", objID.Hex()) // Debugging
		c.JSON(http.StatusNotFound, gin.H{"error": "No active application found"})
		return
	}

	// ✅ Return application status
	c.JSON(http.StatusOK, gin.H{
		"status":  app.Status,
		"meeting": app.Meeting,
		"appId":   app.ID.Hex(),
	})
}

func GetUserApplicationStatus(c *gin.Context) {
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

	var app models.Application
	err = applicationCollection.FindOne(context.TODO(), bson.M{"user_id": objID}).Decode(&app)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No application found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"fullName":  app.FullName,
		"email":     app.Email,
		"carModels": app.CarModels,
		"status":    app.Status,
		"meeting":   app.Meeting,
	})
}

func DeleteApplication(c *gin.Context) {
	userID, exists := c.Get("userID") // ✅ Get user ID from middleware
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// ✅ Convert userID to ObjectID
	userObjID, err := primitive.ObjectIDFromHex(userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format"})
		return
	}

	// ✅ Find and delete application based on user ID
	filter := bson.M{"user_id": userObjID}
	result, err := applicationCollection.DeleteOne(context.TODO(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete application"})
		return
	}

	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No application found to delete"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Application deleted successfully"})
}
