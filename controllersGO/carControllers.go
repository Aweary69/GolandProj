package controllersGO

import (
	"context"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"net/http"
	"strconv"
	"time"

	"CarStore/models" // Update with the correct path to your models
)

var carCollection *mongo.Collection

// SetCarCollection sets the collection for car operations
func SetCarCollection(collection *mongo.Collection) {
	carCollection = collection
}

// FilterCars handles filtering cars based on query parameters
func FilterCars(c *gin.Context) {
	query := c.Request.URL.Query()
	model := query.Get("model")
	yearStr := query.Get("year")
	mileageStr := query.Get("mileage")

	var year, mileage int
	var err error
	if yearStr != "" {
		year, err = strconv.Atoi(yearStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid year"})
			return
		}
	}
	if mileageStr != "" {
		mileage, err = strconv.Atoi(mileageStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mileage"})
			return
		}
	}

	filter := bson.M{}
	if model != "" {
		filter["model"] = model
	}
	if year != 0 {
		filter["year"] = year
	}
	if mileage != 0 {
		filter["mileage"] = bson.M{"$lte": mileage}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var filteredCars []models.Car
	cursor, err := carCollection.Find(ctx, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching cars"})
		return
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &filteredCars); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error decoding cars"})
		return
	}

	c.JSON(http.StatusOK, filteredCars)
}

// GetAllCars retrieves all cars from the database
func GetAllCars(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var cars []models.Car
	cursor, err := carCollection.Find(ctx, bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching cars"})
		return
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &cars); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error decoding cars"})
		return
	}

	c.JSON(http.StatusOK, cars)
}

// GetCarByID retrieves a single car by ID
func GetCarByID(c *gin.Context) {
	id := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid car ID"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var car models.Car
	err = carCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&car)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Car not found"})
		return
	}

	c.JSON(http.StatusOK, car)
}

// CreateCar adds a new car to the database
func CreateCar(c *gin.Context) {
	var car models.Car

	if err := c.ShouldBindJSON(&car); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	car.ID = primitive.NewObjectID()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := carCollection.InsertOne(ctx, car)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error adding car"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Car added successfully", "car": car})
}

// UpdateCar modifies an existing car entry
func UpdateCar(c *gin.Context) {
	id := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid car ID"})
		return
	}

	var carUpdate models.Car
	if err := c.ShouldBindJSON(&carUpdate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	update := bson.M{
		"$set": bson.M{
			"model":   carUpdate.CarModels,
			"year":    carUpdate.Year,
			"mileage": carUpdate.Mileage,
		},
	}

	_, err = carCollection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating car"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Car updated successfully"})
}

// DeleteCar removes a car from the database
func DeleteCar(c *gin.Context) {
	id := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid car ID"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = carCollection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting car"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Car deleted successfully"})
}
