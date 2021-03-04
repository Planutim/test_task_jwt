package helpers

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type TokenHelper struct {
}

type RefreshToken struct {
	UserID       string `bson:"user_id"`
	TokenID      string `bson:"token_id"`
	EncodedToken string `bson:"encoded_token"`
}

//CreateToken creates token for specified userID
func (th *TokenHelper) CreateToken(userID string) (AToken string, RToken string, err error) {
	timeCreated := time.Now()
	md5hash := md5.Sum([]byte(timeCreated.String()))
	md5hashStr := fmt.Sprintf("%x", md5hash)
	AtClaims := jwt.MapClaims{}
	AtClaims["user_id"] = userID
	AtClaims["token_id"] = md5hashStr
	//set at deadline
	AtClaims["exp"] = time.Now().Add(15 * time.Minute).Unix()

	AtToken := jwt.NewWithClaims(jwt.SigningMethodHS512, &AtClaims)

	AtTokenString, err := AtToken.SignedString([]byte(os.Getenv("ACCESS_TOKEN_SECRET")))
	if err != nil {
		return "", "", err
	}

	RtClaims := jwt.MapClaims{}
	RtClaims["user_id"] = userID
	RtClaims["token_id"] = md5hashStr
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
	err = saveRtToken(userID, md5hashStr, rtEncoded)
	if err != nil {
		return "", "", err
	}

	return AtTokenString, RtTokenString, nil
}

//RefreshToken checks and refreshed token for specified userID and refresh token
func (th *TokenHelper) RefreshToken(userID, rtTokenString string) (newAToken string, newRToken string, err error) {
	//delete previous token
	err = deletePreviousToken(userID, rtTokenString)
	if err != nil {
		return "", "", err
	}
	//if all good, return new pair of tokens
	return th.CreateToken(userID)
}

func deletePreviousToken(userID, rtTokenString string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
	if err != nil {
		return err
	}
	defer client.Disconnect(ctx)

	db := client.Database(os.Getenv("MONGODB_DATABASE"))
	tokenCollection := db.Collection("refresh_tokens")

	findResult := tokenCollection.FindOne(ctx, bson.M{
		"user_id":  userID,
		"token_id": rtTokenString,
	})
	if errors.Is(findResult.Err(), mongo.ErrNoDocuments) {
		//not found
		return findResult.Err()
	}
	if findResult.Err() != nil {
		return findResult.Err()
	}
	//delete result
	deleteResult, err := tokenCollection.DeleteOne(ctx, bson.M{
		"user_id":  userID,
		"token_id": rtTokenString,
	})
	if err != nil {
		return err
	}
	if deleteResult.DeletedCount != 1 {
		return errors.New("Could not delete")
	}
	return nil
}

func saveRtToken(userID, tokenID, encodedTokenString string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
	if err != nil {
		return err
	}
	defer client.Disconnect(ctx)
	db := client.Database(os.Getenv("MONGODB_DATABASE"))
	tokenCollection := db.Collection("refresh_tokens")

	refreshToken := &RefreshToken{
		UserID:       userID,
		TokenID:      tokenID,
		EncodedToken: encodedTokenString,
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
