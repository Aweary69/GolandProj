package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Car struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	CarModels []string           `bson:"car_models" json:"carModels"`
	Year      int                `bson:"year" json:"year" binding:"required"`
	Mileage   int                `bson:"mileage" json:"mileage" binding:"required"`
	City      string             `bson:"city" json:"city" binding:"required"`
	Price     float64            `bson:"price" json:"price" binding:"required"`
	OwnerID   primitive.ObjectID `bson:"owner_id" json:"owner_id"`
}
