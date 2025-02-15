package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type User struct {
	ID          primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Name        string               `bson:"name" json:"name" binding:"required"`
	Email       string               `bson:"email" json:"email" binding:"required,email"`
	Password    string               `bson:"password" json:"password" binding:"required"`
	Money       float64              `bson:"money" json:"money"`
	Preferences UserPreferences      `bson:"preferences" json:"preferences"`
	Favorites   []primitive.ObjectID `bson:"favorites" json:"favorites"`
	CreatedAt   time.Time            `bson:"created_at" json:"created_at"`
}

type UserPreferences struct {
	Models  []string `bson:"models" json:"models"`
	City    string   `bson:"city" json:"city"`
	Used    bool     `bson:"used" json:"used"` // Prefers used or new cars
	Year    int      `bson:"year" json:"year"`
	Mileage int      `bson:"mileage" json:"mileage"`
}
