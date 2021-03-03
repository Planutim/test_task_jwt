package handlers

import (
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/Planutim/test_task_jwt/helpers"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

//TokenHandler is handler to server token endpoints
type TokenHandler struct {
	tokenHelper *helpers.TokenHelper
}

//NewTokenHandler creates an instance of TokenHandler
func NewTokenHandler() *TokenHandler {
	return &TokenHandler{
		tokenHelper: &helpers.TokenHelper{},
	}
}

//GetToken sends JSON with token for user specified in request body
func (t *TokenHandler) GetToken(c echo.Context) error {
	userID, err := retrieveUserID(c)
	if err != nil {
		if strings.Contains(err.Error(), "Empty id") {
			return c.JSON(http.StatusBadRequest, echo.Map{
				"message": "No id provided",
			})
		}
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "ID should be in UUID format",
		})
	}

	AtTokenString, RtTokenString, err := t.tokenHelper.CreateToken(userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			// "message": "Could not create token",
			"message": err,
		})
	}

	//Encode rt to base64
	rtsEncoded := base64.StdEncoding.EncodeToString([]byte(RtTokenString))

	return c.JSON(http.StatusOK, echo.Map{
		"access_token":  AtTokenString,
		"refresh_token": rtsEncoded,
	})
}

//RefreshToken refreshes tokens and sens JSON in response
func (t *TokenHandler) RefreshToken(c echo.Context) error {
	userID, err := retrieveUserID(c)
	if err != nil {
		if strings.Contains(err.Error(), "Empty id") {
			return c.JSON(http.StatusBadRequest, echo.Map{
				"message": "No id provided",
			})
		}
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "ID should be in UUID format",
		})
	}
	rtTokenString, err := retrieveToken("refresh", c)
	if err != nil {
		if strings.Contains(err.Error(), "Empty token") {
			return c.JSON(http.StatusBadRequest, echo.Map{
				"message": "No token provided",
			})
		}
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "Wrong token format",
		})
	}

	atToken, err := extractToken("access", userID, rtTokenString)
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "Could not extract access token",
		})
	}

	rtToken, err := extractToken("refresh", userID, rtTokenString)
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "Could not extract refresh token",
		})
	}

	err = verifyToken(userID, atToken)
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "Could not verify access token",
		})
	}
	err = verifyToken(userID, rtToken)
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "Could not verify refresh token",
		})
	}

	err = compareTokens(atToken, rtToken)
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "Not a pair of tokens",
		})
	}

	newAtTokenString, newRtTokenString, err := t.tokenHelper.RefreshToken(userID, rtTokenString)
	if err != nil {
		return c.JSON(http.StatusUnprocessableEntity, echo.Map{
			"message": "Error at /refresh" + err.Error(),
		})
	}

	rtEncoded := base64.StdEncoding.EncodeToString([]byte(newRtTokenString))

	return c.JSON(http.StatusOK, echo.Map{
		"access_token":  newAtTokenString,
		"refresh_token": rtEncoded,
	})
}

func retrieveUserID(c echo.Context) (string, error) {
	idString := c.FormValue("id")

	if idString == "" {
		return "", errors.New("Empty id")
	}
	_, err := uuid.Parse(idString)
	if err != nil {
		c.Logger().Warn(err)
		return "", errors.New("Wrong UUID format")
	}

	return idString, err
}

func retrieveToken(tokenType string, c echo.Context) (string, error) {
	var tokenString string
	if tokenType == "access" {
		tokenString = c.FormValue("access_token")
	} else {
		tokenString = c.FormValue("refresh_token")
	}
	if tokenString == "" {
		return "", errors.New("Empty token")
	}

	rtDecoded, err := base64.StdEncoding.DecodeString(tokenString)
	if err != nil {
		return "", errors.New("Wrong base64 string")
	}
	return string(rtDecoded), nil
}

func extractToken(tokenType string, userID, tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(string(tokenString), func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Wrong signing method")
		}
		switch tokenType {
		case "access":
			return []byte(os.Getenv("ACCESS_TOKEN_SECRET")), nil
		case "refresh":
			return []byte(os.Getenv("REFRESH_TOKEN_SECRET")), nil
		}
		return nil, errors.New("error")
	})

	if err != nil {
		return nil, err
	}
	return token, nil
}

func verifyToken(userID string, token *jwt.Token) error {
	if !token.Valid {
		return errors.New("token expired")
	}
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("error")
	}
	if extractedID, ok := mapClaims["user_id"]; !ok || extractedID != userID {
		return errors.New("error")
	}
	return nil
}

func compareTokens(atToken, rtToken *jwt.Token) error {
	atClaims, ok := atToken.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("error")
	}

	rtClaims, ok := rtToken.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("error")
	}

	atTokenID, ok := atClaims["token_id"]
	if !ok {
		return errors.New("error")
	}
	rtTokenID, ok := rtClaims["token_id"]
	if !ok {
		return errors.New("error")
	}
	if atTokenID != rtTokenID {
		return errors.New("Not equal token_ids")
	}
	return nil
}
