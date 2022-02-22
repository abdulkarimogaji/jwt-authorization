package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Article struct {
	Id     int    `bson:"id,omitempty" json:"id"`
	Title  string `bson:"title" json:"title"`
	Author string `bson:"author" json:"author"`
	Url    string `bson:"url" json:"url"`
}

const Articles = `
	CREATE TABLE IF NOT EXISTS articles(
		Id INTEGER PRIMARY KEY AUTOINCREMENT,
		Title VARCHAR(100) NULL,
		Author VARCHAR(64) NULL,
		Url VARCHAR(1000) NULL
	)
`

const Users = `
	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(100),
		passwordHash VARCHAR(100)
	)
`

func BindingError(err error, c *gin.Context) {
	c.JSON(http.StatusBadRequest, gin.H{
		"error": err.Error(),
	})
}
