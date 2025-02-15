package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type Application struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"userId"` // ✅ Reference to the user
	FullName  string             `bson:"full_name" json:"fullName" binding:"required"`
	Email     string             `bson:"email" json:"email" binding:"required,email"`
	Phone     string             `bson:"phone" json:"phone" binding:"required"`
	CarModels []string           `bson:"car_models" json:"carModels" binding:"required"`
	Year      int                `bson:"year" json:"year" binding:"required"`
	Mileage   int                `bson:"mileage" json:"mileage" binding:"required"`
	Message   string             `bson:"message" json:"message"`
	Status    string             `bson:"status" json:"status"`
	Meeting   *time.Time         `bson:"meeting,omitempty" json:"meeting,omitempty"`
	CreatedAt time.Time          `bson:"created_at" json:"createdAt"`
}
