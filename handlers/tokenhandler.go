package handlers

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/Planutim/test_task_jwt/helpers"
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

func retrieveUserID(c echo.Context) (*uuid.UUID, error) {
	idString := c.Param("id")

	id, err := uuid.Parse(idString)
	if err != nil {
		c.Logger().Warn(err)
		return nil, errors.New("Wrong UUID format")
	}

	return &id, err
}
