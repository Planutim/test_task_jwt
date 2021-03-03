package helpers

import (
	"context"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type TokenHelper struct {
}

type RefreshToken struct {
	UserID       string `bson:"user_id"`
	EncodedToken string `bson:"encoded_token"`
}

//CreateToken creates token for specified userID
func (th *TokenHelper) CreateToken(userID *uuid.UUID) (AToken string, RToken string, err error) {
	AtClaims := jwt.MapClaims{}
	AtClaims["id"] = userID.String()
	//set at deadline
	AtClaims["exp"] = time.Now().Add(15 * time.Minute).Unix()

	AtToken := jwt.NewWithClaims(jwt.SigningMethodHS512, &AtClaims)

	AtTokenString, err := AtToken.SignedString([]byte(os.Getenv("ACCESS_TOKEN_SECRET")))
	if err != nil {
		return "", "", err
	}

	RtClaims := jwt.MapClaims{}
	RtClaims["id"] = userID.String()
	//set rt deadline
	RtClaims["exp"] = time.Now().Add(7 * 24 * time.Hour).Unix()

	RtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &RtClaims)

	RtTokenString, err := RtToken.SignedString([]byte(os.Getenv("REFRESH_TOKEN_SECRET")))
	if err != nil {
		return "", "", err
	}

	//encode rt to bcrypt
	rtEncoded, err := encodeRtToken(RtTokenString)
	if err != nil {
		return "", "", err
	}
	//Save rt to MongoDB
	err = saveRtToken(userID.String(), rtEncoded)
	if err != nil {
		return "", "", err
	}

	return AtTokenString, RtTokenString, nil
}

func saveRtToken(userID, encodedTokenString string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
	defer client.Disconnect(ctx)
	if err != nil {
		return err
	}
	db := client.Database(os.Getenv("MONGODB_DATABASE"))
	tokenCollection := db.Collection("refresh_tokens")

	refreshToken := &RefreshToken{
		UserID:       userID,
		EncodedToken: string(encodedTokenString),
	}
	_, err = tokenCollection.InsertOne(ctx, refreshToken)
	if err != nil {
		return err
	}

	return nil
}

func encodeRtToken(tokenString string) (string, error) {
	encodedTokenString, err := bcrypt.GenerateFromPassword([]byte(tokenString), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(encodedTokenString), nil
}
