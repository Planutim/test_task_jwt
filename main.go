package main

import (
	"log"
	"os"

	"github.com/Planutim/test_task_jwt/handlers"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

/*
Тестовое задание на позицию Junior Backend Developer

**Используемые технологии:**

- Go
- JWT
- MongoDB

**Задание:**

Написать часть сервиса аутентификации.

Два REST маршрута:

- Первый маршрут выдает пару Access, Refresh токенов для пользователя сидентификатором (GUID) указанным в параметре запроса
- Второй маршрут выполняет Refresh операцию на пару Access, Refreshтокенов

**Требования:**

Access токен тип JWT, алгоритм SHA512, хранить в базе строго запрещено.

Refresh токен тип произвольный, формат передачи base64, хранится в базеисключительно в виде bcrypt хеша, должен быть защищен от изменения настороне клиента и попыток повторного использования.

Access, Refresh токены обоюдно связаны, Refresh операцию для Access токена можно выполнить только тем Refresh токеном который был выдан вместе с ним.

**Результат:**

Результат выполнения задания нужно предоставить в виде исходного кода на Github.
*/

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Could not load environment variables!")
	}

	e := echo.New()
	tokenHandler := handlers.NewTokenHandler()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.POST("/token", tokenHandler.GetToken)
	e.POST("/token/refresh", tokenHandler.RefreshToken)

	e.Logger.Fatal(e.Start(":" + os.Getenv("APP_PORT")))
}
